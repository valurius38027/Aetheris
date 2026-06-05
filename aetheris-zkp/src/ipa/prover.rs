use std::io;

use halo2_backend::poly::commitment::{Params, Prover as ProverTrait, MSM as MSMTrait, ParamsProver};
use halo2_backend::poly::query::ProverQuery;
use halo2_backend::transcript::{ChallengeScalar, EncodedChallenge, TranscriptWrite};
use halo2_middleware::zal::traits::MsmAccel;
use halo2_proofs::arithmetic::{CurveExt, Field};
use halo2_proofs::halo2curves::group::{Curve as GroupCurve, Group};
use halo2_proofs::halo2curves::CurveAffine;
use rand_core::RngCore;

use crate::ipa::commitment::{ParamsIPA, ThetaChallenge, RoundChallenge};
use crate::dtrace;

#[derive(Debug)]
pub struct ProverIPA<'params, C: CurveAffine> {
    params: &'params ParamsIPA<C>,
}

fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len(), "inner_product: vectors must have equal length");
    let mut acc = F::ZERO;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc + *x * *y;
    }
    acc
}

impl<'params, C: CurveAffine> ProverTrait<'params, crate::ipa::commitment::CommitmentSchemeIPA<C>>
    for ProverIPA<'params, C>
where
    C::CurveExt: CurveExt,
{
    fn new(params: &'params ParamsIPA<C>) -> Self {
        ProverIPA { params }
    }

    fn create_proof_with_engine<
        'com,
        Ch: EncodedChallenge<C>,
        T: TranscriptWrite<C, Ch>,
        R,
        I,
    >(
        &self,
        engine: &impl MsmAccel<C>,
        mut rng: R,
        transcript: &mut T,
        queries: I,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = ProverQuery<'com, C>> + Clone,
        R: RngCore,
    {
        let params = self.params;
        let h = *params.h();
        let h_proj = h.to_curve();
        let all_queries: Vec<ProverQuery<'com, C>> = queries.into_iter().collect();
        let mut seen = std::collections::BTreeSet::new();
        let unique_points: Vec<&ProverQuery<'com, C>> = all_queries
            .iter()
            .filter(|q| seen.insert(q.point))
            .collect();

        for (_pt_idx, &first_q) in unique_points.iter().enumerate() {
            let point = first_q.point;

            let point_queries: Vec<&ProverQuery<'com, C>> = all_queries
                .iter()
                .filter(|q| q.point == point)
                .collect();

            // Use the full params domain size for IPA rounds, not the query
            // polynomial length. The commitment uses all params.n() generators,
            // so the IPA proof must be over the same generator set.
            let n = self.params.n() as usize;

            let k = self.params.k();
            transcript.write_scalar(C::ScalarExt::from(k as u64))?;

            let theta: ChallengeScalar<C, ThetaChallenge> =
                transcript.squeeze_challenge_scalar();
            let theta_val = *theta;

            let mut b = vec![C::ScalarExt::ONE; n];
            for i in 1..n {
                b[i] = b[i - 1] * point;
            }

            // Compute combined a vector and initial cumulative blind.
            // Combined commitment: P = sum_j theta^j * (MSM(poly_j, g) + blind_j * H)
            //                    = MSM(a, g) + (sum_j theta^j * blind_j) * H
            // The initial cumulative blind r' must equal sum_j theta^j * blind_j.
            let mut combined = vec![C::ScalarExt::ZERO; n];
            let mut pow = C::ScalarExt::ONE;
            let mut r_prime: C::ScalarExt = C::ScalarExt::ZERO;
            for (q_idx, q) in point_queries.iter().enumerate() {
                let poly_len = q.poly.values.len();
                dtrace!("[IPA-PROVER] q[{}] point={:?} poly_len={} n={} blind={:?}",
                    q_idx, q.point, poly_len, n, q.blind.0);
                for (c, pv) in combined.iter_mut().zip(q.poly.values.iter()) {
                    *c += pow * *pv;
                }
                r_prime += pow * q.blind.0;
                pow = pow * theta_val;
            }
            if crate::diagnostics::dbg_enabled() {
                eprintln!("[IPA-PROVER-DBG] r_prime_initial={:?} (n_q={})", r_prime, point_queries.len());
            }

            let g = params.g();
            let u_aff = *params.u();
            let u_proj = u_aff.to_curve();

            let mut a_cur = combined;
            let mut b_cur = b;
            let mut g_cur: Vec<C> = g.to_vec();
            let mut len = n;
            let mut cumulative_correction: C::ScalarExt = C::ScalarExt::ZERO;

            // Collect L, R, x for prover self-check
            let mut l_points_prover: Vec<C> = Vec::new();
            let mut r_points_prover: Vec<C> = Vec::new();
            let mut challenges_prover: Vec<C::ScalarExt> = Vec::new();
            let mut combined_eval_prover: C::ScalarExt = C::ScalarExt::ZERO;
            for q in point_queries.iter() {
                let mut ev = C::ScalarExt::ZERO;
                for coeff in q.poly.values.iter().rev() {
                    ev = ev * q.point + *coeff;
                }
                let mut pow_eval = C::ScalarExt::ONE;
                if combined_eval_prover == C::ScalarExt::ZERO {
                    pow_eval = C::ScalarExt::ONE;
                }
                let _ = pow_eval;
            }
            // Actually compute combined_eval using the same fold-aware loop:
            // Each query contributes pow * eval(q) to combined_eval, where pow is theta^j.
            // Note: combined_eval is evaluated independently of the prover's combined a vector
            // (since the verifier recomputes it from q.eval). The prover's combined vector is
            // a = sum theta^j * poly_j (in coefficient form), and combined_eval = sum theta^j * poly_j(point).
            // We compute combined_eval here by reusing the pow from the r' loop:
            let mut pow_eval = C::ScalarExt::ONE;
            for q in point_queries.iter() {
                let mut ev = C::ScalarExt::ZERO;
                for coeff in q.poly.values.iter().rev() {
                    ev = ev * q.point + *coeff;
                }
                combined_eval_prover += pow_eval * ev;
                pow_eval = pow_eval * theta_val;
            }
            let _ = combined_eval_prover; // suppress unused warning

            while len > 1 {
                let half = len / 2;
                let (a_lo, a_hi) = a_cur.split_at(half);
                let (b_lo, b_hi) = b_cur.split_at(half);
                let (g_lo, g_hi) = g_cur.split_at(half);

                let c_l = inner_product(a_lo, b_hi);
                let c_r = inner_product(a_hi, b_lo);

                // Sample per-round blinding scalars s_j, s'_j. These ensure L,R
                // are non-identity even when a_lo/a_hi are zero, and they
                // contribute to the cumulative H term r'.
                let s_j: C::ScalarExt = C::ScalarExt::random(&mut rng);
                let s_prime_j: C::ScalarExt = C::ScalarExt::random(&mut rng);

                let l_msm = engine.msm(a_lo, g_hi);
                let l_proj = l_msm + u_proj * c_l + h_proj * s_j;
                let l_aff = l_proj.to_affine();
                if crate::diagnostics::dbg_enabled() {
                    let l_x = l_aff.coordinates().map(|c| *c.x());
                    if bool::from(l_x.is_none()) {
                        eprintln!("[IPA-PROVER-DBG] L is point at infinity! len={}, a_lo_zero={}, c_l={:?}",
                            len, a_lo.iter().all(|x| bool::from(x.is_zero())), c_l);
                    }
                    if len == 2048 && point_queries.len() == 15 {
                        eprintln!("[IPA-PROVER-DBG] round 0 L (15q): l.x={:?} c_l={:?} s_j={:?}", l_x, c_l, s_j);
                    }
                }
                transcript.write_point(l_aff)?;
                if crate::diagnostics::dbg_enabled() {
                    l_points_prover.push(l_aff);
                }

                let r_msm = engine.msm(a_hi, g_lo);
                let r_proj = r_msm + u_proj * c_r + h_proj * s_prime_j;
                let r_aff = r_proj.to_affine();
                if crate::diagnostics::dbg_enabled() {
                    if r_aff.coordinates().is_none().into() {
                        eprintln!("[IPA-PROVER-DBG] R is point at infinity! len={}, a_hi_zero={}, c_r={:?}",
                            len, a_hi.iter().all(|x| bool::from(x.is_zero())), c_r);
                    }
                }
                transcript.write_point(r_aff)?;
                if crate::diagnostics::dbg_enabled() {
                    r_points_prover.push(r_aff);
                }

                let x: ChallengeScalar<C, RoundChallenge> =
                    transcript.squeeze_challenge_scalar();
                let x_val = *x;
                if crate::diagnostics::dbg_enabled() {
                    challenges_prover.push(x_val);
                }
                let x_inv: C::ScalarExt = Option::from(x_val.invert()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "IPA prover: zero challenge in round")
                })?;

                // Update cumulative blind: verifier folds with x^{-1} on L and x on R,
                // so H contribution from this round is (x^{-1} * s_j + x * s'_j) * H.
                r_prime = r_prime + x_inv * s_j + x_val * s_prime_j;
                cumulative_correction = cumulative_correction + x_inv * c_l + x_val * c_r;

            let mut a_new = Vec::with_capacity(half);
            let mut b_new = Vec::with_capacity(half);
            let mut g_new = Vec::with_capacity(half);
            for j in 0..half {
                a_new.push(a_lo[j] + x_val * a_hi[j]);
                b_new.push(b_lo[j] + x_inv * b_hi[j]);
                let g_proj = g_lo[j].to_curve() + g_hi[j].to_curve() * x_inv;
                g_new.push(g_proj.to_affine());
            }
            a_cur = a_new;
            b_cur = b_new;
            g_cur = g_new;
            len = half;
        }

        // Save g_final and b_final for prover self-check
        let g_final_prover: C = g_cur[0];

            transcript.write_scalar(a_cur[0])?;
            // Write cumulative H-blind to transcript so verifier can balance the equation.
            transcript.write_scalar(r_prime)?;
            if crate::diagnostics::dbg_enabled() {
                let prover_h_x = h.coordinates().map(|c| *c.x());
                let a_final_val = a_cur[0];
                let b_final_val = b_cur[0];
                let ab_product = a_final_val * b_final_val;
                let expected_v = ab_product - cumulative_correction;
                eprintln!("[IPA-PROVER-DBG] a_final={:?} b_final={:?} a*b={:?} cum_correction={:?} expected_v={:?}",
                    a_final_val, b_final_val, ab_product, cumulative_correction, expected_v);
                eprintln!("[IPA-PROVER-DBG] wrote a_final={:?} r_prime={:?} (n_q={}) prover_h.is_id={} h.x={:?}",
                    a_cur[0], r_prime, point_queries.len(),
                    bool::from(h.is_identity()), prover_h_x);

                // PROVER SELF-CHECK: reconstruct what the verifier's msm would be using the
                // prover's own commitments (which the prover knows from keygen/commitment).
                // The prover can build the msm by:
                // 1. For each query: combined_msm += pow * c where c = MSM(poly, g) + blind * H
                // 2. Add L, R contributions
                // 3. Add u_scalar * U
                // 4. Add -a * g_final
                // 5. Add -r' * H
                // If the prover's msm is 0, the prover's proof is valid; the verifier should
                // also see 0. If not, the prover's proof is wrong.
                use crate::ipa::commitment::MSMIPA;
                use halo2_middleware::zal::impls::H2cEngine;

                // Reconstruct the prover's combined_msm EXACTLY as the verifier does:
                // For each query, prover has Commitment(c) where c = engine.msm(poly, g) + blind * H
                // The verifier has the same Commitment(c) for non-MSM queries, or an MSM for h_commitment.
                // The verifier computes combined_msm += pow * c. The result is the same point
                // regardless of how the c is decomposed. Let's reconstruct the prover's combined_msm
                // as if the verifier's queries were all Commitments (the prover doesn't have access
                // to the verifier's h_commitment MSM structure).
                let mut combined_msm = MSMIPA::<C>::new();
                let mut pow3 = C::ScalarExt::ONE;
                for (q_idx, q) in point_queries.iter().enumerate() {
                    let poly_msm = engine.msm(&q.poly.values, &params.g()[..q.poly.values.len()]);
                    let c: C::CurveExt = poly_msm + (C::CurveExt::from(h) * q.blind.0);
                    let c_x: Option<<C as halo2_proofs::arithmetic::CurveAffine>::Base> =
                        c.to_affine().coordinates().map(|cc| *cc.x()).into();
                    eprintln!("[IPA-PROVER-DBG] c[{}] x={:?} blind={:?} poly_len={} (n_q={})",
                        q_idx, c_x, q.blind.0, q.poly.values.len(), point_queries.len());

                    // CROSS-CHECK: call params.commit (Coeff version) on q.poly and q.blind
                    // and compare to our c. If they differ, q.poly is NOT the same as the
                    // committed poly.
                    let c_via_commit: C::CurveExt = params.commit(engine, q.poly, q.blind);
                    let c_commit_aff = c_via_commit.to_affine();
                    let c_commit_x: Option<<C as halo2_proofs::arithmetic::CurveAffine>::Base> =
                        c_commit_aff.coordinates().map(|cc| *cc.x()).into();
                    let cx_match = c_x == c_commit_x;
                    eprintln!("[IPA-PROVER-DBG] c[{}] via commit() x={:?} cx={:?} match={} (n_q={})",
                        q_idx, c_commit_x, c_x, cx_match, point_queries.len());

                    combined_msm.append_term(pow3, c);
                    pow3 = pow3 * theta_val;
                }
                eprintln!("[IPA-PROVER-DBG] combined_msm.terms={} (verifier has same data)", combined_msm.bases.len());
                let combined_eval_p = combined_msm.eval(&H2cEngine::new());
                let combined_p_x: Option<<C as halo2_proofs::arithmetic::CurveAffine>::Base> =
                    combined_eval_p.to_affine().coordinates().map(|c| *c.x()).into();
                eprintln!("[IPA-PROVER-DBG] combined_msm.eval() is_id={} x={:?} (n_q={})",
                    bool::from(combined_eval_p.is_identity()), combined_p_x, point_queries.len());

                // Check if prover's combined_msm matches the verifier's combined_msm.eval() point.
                // We do this by computing engine.msm(combined_msm.scalars, combined_msm.bases) once more
                // and checking if the point is the same.
                // Actually, the verifier sees a 15+2-term msm. Let me reconstruct the verifier's
                // view of combined_msm and compare. We don't have the h_pieces in the prover, but
                // we can simulate the verifier's structure.

                // Now reconstruct the msm EXACTLY as the verifier does:
                // 1. combined_msm
                // 2. Add x_inv * L + x * R per round
                // 3. Add (v - a*b) * U
                // 4. Add -a * g_final
                // 5. Add -r' * H
                let mut provers_msm = MSMIPA::<C>::new();
                provers_msm.add_msm(&combined_msm);
                for (i, _) in l_points_prover.iter().enumerate() {
                    let x: C::ScalarExt = challenges_prover[i];
                    let x_inv: C::ScalarExt = Option::from(x.invert()).unwrap();
                    provers_msm.append_term(x_inv, l_points_prover[i].to_curve());
                    provers_msm.append_term(x, r_points_prover[i].to_curve());
                }
                let u_scalar_prover = combined_eval_prover - a_final_val * b_final_val;
                provers_msm.append_term(u_scalar_prover, u_proj);
                provers_msm.append_term(-a_final_val, g_final_prover.to_curve());
                provers_msm.append_term(-r_prime, h.to_curve());

                // Build the prover's view of the msm
                let mut provers_msm = MSMIPA::<C>::new();
                provers_msm.add_msm(&combined_msm);
                // Add L, R
                for (i, _) in l_points_prover.iter().enumerate() {
                    let x: C::ScalarExt = challenges_prover[i];
                    let x_inv: C::ScalarExt = Option::from(x.invert()).unwrap();
                    provers_msm.append_term(x_inv, l_points_prover[i].to_curve());
                    provers_msm.append_term(x, r_points_prover[i].to_curve());
                }
                // Add U
                let u_scalar_prover = combined_eval_prover - a_final_val * b_final_val;
                provers_msm.append_term(u_scalar_prover, u_proj);
                // Add -a * g
                provers_msm.append_term(-a_final_val, g_final_prover.to_curve());
                // Add -r' * H
                provers_msm.append_term(-r_prime, h.to_curve());

                let provers_eval = provers_msm.eval(&H2cEngine::new());
                let is_id_choice = provers_eval.is_identity();
                eprintln!("[IPA-PROVER-DBG] PROVER msm.eval() is_id={} (n_q={})",
                    bool::from(is_id_choice), point_queries.len());
            }
        }

        Ok(())
    }
}
