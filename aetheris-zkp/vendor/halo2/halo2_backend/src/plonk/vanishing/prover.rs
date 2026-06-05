use std::{collections::HashMap, iter};

use crate::plonk::Error;
use group::Curve;
use halo2_middleware::ff::Field;
use halo2_middleware::zal::{impls::PlonkEngine, traits::MsmAccel};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use super::Argument;
use crate::{
    arithmetic::{eval_polynomial, parallelize, CurveAffine},
    multicore::current_num_threads,
    plonk::ChallengeX,
    poly::{
        commitment::{Blind, ParamsProver},
        Coeff, EvaluationDomain, ExtendedLagrangeCoeff, Polynomial, ProverQuery,
    },
    transcript::{EncodedChallenge, TranscriptWrite},
};

pub(in crate::plonk) struct Committed<C: CurveAffine> {
    random_poly: Polynomial<C::Scalar, Coeff>,
    random_blind: Blind<C::Scalar>,
}

pub(in crate::plonk) struct Constructed<C: CurveAffine> {
    h_pieces: Vec<Polynomial<C::Scalar, Coeff>>,
    h_blinds: Vec<Blind<C::Scalar>>,
    committed: Committed<C>,
}

pub(in crate::plonk) struct Evaluated<C: CurveAffine> {
    h_poly: Polynomial<C::Scalar, Coeff>,
    /// Cumulative blind for the combined h_poly: sum_{j=0..n-1}(xn^j * h_blinds[j])
    /// This matches the verifier's fold: h_commitment = sum(xn^j * c[j]) = MSM(h_poly, g) + cumulative·H
    h_cumulative_blind: C::Scalar,
    committed: Committed<C>,
}

impl<C: CurveAffine> Argument<C> {
    pub(in crate::plonk) fn commit<
        P: ParamsProver<C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
    >(
        engine: &impl MsmAccel<C>,
        params: &P,
        domain: &EvaluationDomain<C::Scalar>,
        mut rng: R,
        transcript: &mut T,
    ) -> Result<Committed<C>, Error> {
        // Sample a random polynomial of degree n - 1
        let n = 1usize << domain.k() as usize;
        let mut rand_vec = vec![C::Scalar::ZERO; n];

        let num_threads = current_num_threads();
        let chunk_size = n / num_threads;
        let thread_seeds = (0..)
            .step_by(chunk_size + 1)
            .take(n % num_threads)
            .chain(
                (chunk_size != 0)
                    .then(|| ((n % num_threads) * (chunk_size + 1)..).step_by(chunk_size))
                    .into_iter()
                    .flatten(),
            )
            .take(num_threads)
            .zip(iter::repeat_with(|| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                ChaCha20Rng::from_seed(seed)
            }))
            .collect::<HashMap<_, _>>();

        parallelize(&mut rand_vec, |chunk, offset| {
            let mut rng = thread_seeds[&offset].clone();
            chunk
                .iter_mut()
                .for_each(|v| *v = C::Scalar::random(&mut rng));
        });

        let random_poly: Polynomial<C::Scalar, Coeff> = domain.coeff_from_vec(rand_vec);

        // Sample a random blinding factor
        let random_blind = Blind(C::Scalar::random(rng));

        // Commit
        let c = params
            .commit(engine, &random_poly, random_blind)
            .to_affine();
        transcript.write_point(c)?;

        Ok(Committed { random_poly, random_blind })
    }
}

impl<C: CurveAffine> Committed<C> {
    pub(in crate::plonk) fn construct<
        P: ParamsProver<C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
        M: MsmAccel<C>,
    >(
        self,
        engine: &PlonkEngine<C, M>,
        params: &P,
        domain: &EvaluationDomain<C::Scalar>,
        h_poly: Polynomial<C::Scalar, ExtendedLagrangeCoeff>,
        mut rng: R,
        transcript: &mut T,
    ) -> Result<Constructed<C>, Error> {
        // DIAGNOSTIC: Save f_coset (pre-division) for later analysis
        if crate::diagnostics::dbg_enabled() {
            let f_coset_for_diag = h_poly.values.clone();
            // Build the f polynomial (full, untruncated) via IFFT
            let f_coeff_full = domain.extended_to_coeff(
                Polynomial::<C::Scalar, ExtendedLagrangeCoeff> {
                    values: f_coset_for_diag.clone(),
                    _marker: std::marker::PhantomData,
                }
            );
            // Evaluate f at standard domain points ω^i to check satisfiability
            let n = 1usize << domain.k();
            let omega = domain.get_omega();
            let mut f_nonzero_count = 0;
            let mut first_nonzero_indices: Vec<usize> = Vec::new();
            let mut omega_pow = C::Scalar::ONE;
            for i in 0..n {
                let f_at_omega_i = {
                    let mut acc = C::Scalar::ZERO;
                    for c in f_coeff_full.iter().rev() {
                        acc = acc * omega_pow + *c;
                    }
                    acc
                };
                if !f_at_omega_i.is_zero_vartime() {
                    f_nonzero_count += 1;
                    if first_nonzero_indices.len() < 30 {
                        first_nonzero_indices.push(i);
                        eprintln!("[DOMAIN-CHECK] f(ω^{}) = {:?}", i, f_at_omega_i);
                    }
                }
                omega_pow *= &omega;
            }
            eprintln!("[DOMAIN-CHECK] f at domain points: nonzero={}/{}", f_nonzero_count, n);
            eprintln!("[DOMAIN-CHECK] first nonzero indices: {:?}", first_nonzero_indices);

            // Diagnostic 3: Identify which expression(s) are non-zero at violated domain points
            // We need: f(X) = Σ expression_i(X) * y^i
            // If only one expression is non-zero at a domain point, we can identify it
            // by testing f / y^i for various i.
            // f(ω^0) is one value; f(ω^0) / y^0 = expression_0 + Σ_{i>0} expression_i * y^i
            // We can't directly invert, but if only one expression is non-zero, the
            // structure is detectable.
            // Instead, let me try: evaluate each expression_i at the violated points
            // by using y-division. f(ω^0) * y^(-N) where N is the LAST index should
            // give expression_0 if all other expressions are 0.
            // Actually, let me use a simpler approach: just print the ratio f(ω^0)/f(ω^2042)
            // which might reveal something.
            let omega_0 = C::Scalar::ONE;
            let omega_2042 = {
                let mut p = C::Scalar::ONE;
                for _ in 0..2042 {
                    p *= &omega;
                }
                p
            };
            let f0 = {
                let mut acc = C::Scalar::ZERO;
                for c in f_coeff_full.iter().rev() {
                    acc = acc * omega_0 + *c;
                }
                acc
            };
            let f2042 = {
                let mut acc = C::Scalar::ZERO;
                for c in f_coeff_full.iter().rev() {
                    acc = acc * omega_2042 + *c;
                }
                acc
            };
            eprintln!("[DOMAIN-DETAIL] f(ω^0)={:?}", f0);
            eprintln!("[DOMAIN-DETAIL] f(ω^2042)={:?}", f2042);
        }

        // Divide by t(X) = X^{params.n} - 1.
        let h_coset = domain.divide_by_vanishing_poly(h_poly);

        // Obtain final h(X) polynomial via IFFT
        let mut h_poly = domain.extended_to_coeff(h_coset);

        // Truncate to n * quotient_poly_degree
        if crate::diagnostics::dbg_enabled() {
            let h_len = h_poly.len();
            eprintln!("[IFFT-DC] h_poly len={} trailing[4090..]=", h_len);
            for i in 4090..h_len.min(4100) {
                eprintln!("[IFFT-DC]   h[{}]={:?}", i, h_poly[i]);
            }
            if h_len > 4100 {
                eprintln!("[IFFT-DC]   ... (truncated)");
            }
        }
        h_poly.truncate(((1u64 << domain.k()) as usize) * domain.get_quotient_poly_degree());

        // Split h(X) up into pieces
        let h_pieces = h_poly
            .chunks_exact(params.n() as usize)
            .map(|v| domain.coeff_from_vec(v.to_vec()))
            .collect::<Vec<_>>();
        drop(h_poly);
        let h_blinds: Vec<_> = h_pieces
            .iter()
            .map(|_| Blind(C::Scalar::random(&mut rng)))
            .collect();

        // Compute commitments to each h(X) piece
        let h_commitments = {
            let h_commitments_projective: Vec<_> = h_pieces
                .iter()
                .zip(h_blinds.iter())
                .map(|(h_piece, blind)| params.commit(&engine.msm_backend, h_piece, *blind))
                .collect();
            let mut h_commitments = vec![C::identity(); h_commitments_projective.len()];
            C::Curve::batch_normalize(&h_commitments_projective, &mut h_commitments);
            if crate::diagnostics::dbg_enabled() {
                for (i, hp) in h_pieces.iter().enumerate() {
                    let all_zero = hp.values.iter().all(|v| bool::from(v.is_zero()));
                    eprintln!("[H-DBG] piece[{}]: len={}, all_zero={}, first5={:?}",
                        i, hp.values.len(), all_zero,
                        &hp.values[..5.min(hp.values.len())]);
                }
            }
            h_commitments
        };

        // Hash each h(X) piece
        for c in h_commitments {
            transcript.write_point(c)?;
        }

        Ok(Constructed {
            h_pieces,
            h_blinds,
            committed: self,
        })
    }
}

impl<C: CurveAffine> Constructed<C> {
    pub(in crate::plonk) fn evaluate<E: EncodedChallenge<C>, T: TranscriptWrite<C, E>>(
        self,
        x: ChallengeX<C>,
        xn: C::Scalar,
        domain: &EvaluationDomain<C::Scalar>,
        transcript: &mut T,
    ) -> Result<Evaluated<C>, Error> {
        let h_poly = self
            .h_pieces
            .iter()
            .rev()
            .fold(domain.empty_coeff(), |acc, eval| acc * xn + eval);

        // Compute cumulative h_blind matching the prover's h_poly fold.
        // The prover computes h_poly = iter().rev().fold(empty, |acc, eval| acc * xn + eval)
        // Processing h_pieces[n-1], ..., h_pieces[0], this yields:
        //   h_poly = h_pieces[0] + xn*h_pieces[1] + xn^2*h_pieces[2] + ... + xn^(n-1)*h_pieces[n-1]
        //          = sum_{i=0}^{n-1} xn^i * h_pieces[i]
        // The verifier's fold is identical (iter().rev() with acc.scale(xn) + append_term(1, commitment)),
        // so the verifier computes h_commitment = sum_{i=0}^{n-1} xn^i * h_commitments[i].
        // Since h_commitments[i] = engine.msm(h_pieces[i], g) + h_blinds[i]*H,
        // we need h_cumulative_blind = sum_{i=0}^{n-1} xn^i * h_blinds[i] for the H-component to match.
        let mut h_cumulative_blind = C::Scalar::ZERO;
        for (i, blind) in self.h_blinds.iter().enumerate() {
            // weight = xn^i
            let exp = i as u32;
            let weight = xn.pow_vartime([exp as u64]);
            h_cumulative_blind += weight * blind.0;
        }

        let random_eval = eval_polynomial(&self.committed.random_poly, *x);
        transcript.write_scalar(random_eval)?;

        let h_eval = eval_polynomial(&h_poly, *x);

        if crate::diagnostics::dbg_enabled() {
            eprintln!("[PROVER-H] h_eval={:?} xn={:?} x={:?}", h_eval, xn, *x);
        }

        transcript.write_scalar(h_eval)?;

        Ok(Evaluated {
            h_poly,
            h_cumulative_blind,
            committed: self.committed,
        })
    }
}

impl<C: CurveAffine> Evaluated<C> {
    pub(in crate::plonk) fn open(
        &self,
        x: ChallengeX<C>,
    ) -> impl Iterator<Item = ProverQuery<'_, C>> + Clone {
        iter::empty()
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.h_poly,
                blind: Blind(self.h_cumulative_blind),
            }))
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.committed.random_poly,
                blind: self.committed.random_blind,
            }))
    }
}
