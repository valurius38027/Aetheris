use std::marker::PhantomData;

use halo2_backend::poly::commitment::{MSM, ParamsVerifier, Verifier};
use halo2_backend::poly::query::{CommitmentReference, VerifierQuery};
use halo2_backend::poly::Error;
use halo2_backend::transcript::{ChallengeScalar, EncodedChallenge, TranscriptRead};
use halo2_middleware::ff::PrimeField;
use halo2_proofs::arithmetic::{CurveExt, Field};
use halo2_proofs::halo2curves::group::Curve as GroupCurve;
use halo2_proofs::halo2curves::CurveAffine;

use crate::ipa::commitment::{derive_point, CommitmentSchemeIPA, GuardIPA, MSMIPA, ParamsIPA, ThetaChallenge, RoundChallenge};

#[derive(Debug)]
pub struct VerifierIPA<C: CurveAffine> {
    _marker: PhantomData<C>,
}

impl<'params, C: CurveAffine> Verifier<'params, CommitmentSchemeIPA<C>> for VerifierIPA<C>
where
    C::CurveExt: CurveExt,
{
    type Guard = GuardIPA<C>;
    type MSMAccumulator = MSMIPA<C>;

    fn new() -> Self {
        VerifierIPA {
            _marker: PhantomData,
        }
    }

    fn verify_proof<
        'com,
        Ch: EncodedChallenge<C>,
        T: TranscriptRead<C, Ch>,
        I,
    >(
        &self,
        transcript: &mut T,
        queries: I,
        mut msm: MSMIPA<C>,
    ) -> Result<GuardIPA<C>, Error>
    where
        'params: 'com,
        I: IntoIterator<
                Item = VerifierQuery<'com, C, <ParamsIPA<C> as ParamsVerifier<'params, C>>::MSM>,
            > + Clone,
    {
        let all_queries: Vec<VerifierQuery<'com, C, MSMIPA<C>>> = queries.into_iter().collect();
        let mut seen = std::collections::BTreeSet::new();
        let unique_points: Vec<&VerifierQuery<'com, C, MSMIPA<C>>> = all_queries
            .iter()
            .filter(|q| seen.insert(q.point))
            .collect();

        for &first_q in &unique_points {
            let point = first_q.point;

            let point_queries: Vec<&VerifierQuery<'com, C, MSMIPA<C>>> = all_queries
                .iter()
                .filter(|q| q.point == point)
                .collect();

            // Read k (number of IPA rounds = log2(n)) written by prover
            let k_raw: C::ScalarExt =
                transcript.read_scalar().map_err(|_| Error::OpeningError)?;
            let k_repr = PrimeField::to_repr(&k_raw);
            let k_bytes = k_repr.as_ref();
            if k_bytes.len() < 4 {
                return Err(Error::OpeningError);
            }
            let mut k_buf = [0u8; 4];
            k_buf.copy_from_slice(&k_bytes[..4]);
            let k = u32::from_le_bytes(k_buf) as usize;
            if k >= 32 {
                return Err(Error::OpeningError);
            }
            let n = 1 << k;

            let theta: ChallengeScalar<C, ThetaChallenge> =
                transcript.squeeze_challenge_scalar();
            let theta_val = *theta;

            // Build combined commitment MSM and combined eval (same theta folding as prover)
            let mut combined_msm = MSMIPA::new();
            let mut combined_eval = C::ScalarExt::ZERO;
            let mut pow = C::ScalarExt::ONE;
            for q in &point_queries {
                match q.commitment {
                    CommitmentReference::Commitment(c) => {
                        combined_msm.append_term(pow, (*c).to_curve());
                    }
                    CommitmentReference::MSM(msm_ref) => {
                        let mut m = msm_ref.clone();
                        m.scale(pow);
                        combined_msm.add_msm(&m);
                    }
                }
                combined_eval += pow * q.eval;
                pow *= theta_val;
            }

            // Read L_i, R_i and squeeze x_i for each round
            let mut l_points = Vec::with_capacity(k);
            let mut r_points = Vec::with_capacity(k);
            let mut challenges = Vec::with_capacity(k);
            for _ in 0..k {
                let l = transcript.read_point().map_err(|_| Error::OpeningError)?;
                let r = transcript.read_point().map_err(|_| Error::OpeningError)?;
                let x: ChallengeScalar<C, RoundChallenge> =
                    transcript.squeeze_challenge_scalar();
                l_points.push(l);
                r_points.push(r);
                challenges.push(*x);
            }

            let a_final: C::ScalarExt =
                transcript.read_scalar().map_err(|_| Error::OpeningError)?;

            // Compute b = powers of the evaluation point
            let mut b_cur = vec![C::ScalarExt::ONE; n];
            for i in 1..n {
                b_cur[i] = b_cur[i - 1] * point;
            }

            // Derive G_i from hash_to_curve (same deterministic derivation as ParamsIPA)
            let mut g_cur: Vec<C> = Vec::with_capacity(n);
            for i in 0..n {
                let mut tag = b"g-".to_vec();
                tag.extend_from_slice(&i.to_le_bytes());
                g_cur.push(derive_point::<C>("aetheris-ipa-g", &tag));
            }

            let u = derive_point::<C>("aetheris-ipa-u", b"u");

            // Fold b and G through the IPA challenges (same folding as prover)
            let mut len = n;
            for i in 0..k {
                let half = len / 2;
                let x_inv: C::ScalarExt = Option::from(challenges[i].invert()).ok_or(Error::OpeningError)?;
                let (b_lo, b_hi) = b_cur.split_at(half);
                let (g_lo, g_hi) = g_cur.split_at(half);

                let mut b_new = Vec::with_capacity(half);
                let mut g_new = Vec::with_capacity(half);
                for j in 0..half {
                    b_new.push(b_lo[j] + x_inv * b_hi[j]);
                    let g_proj = g_lo[j].to_curve() + g_hi[j].to_curve() * x_inv;
                    g_new.push(g_proj.to_affine());
                }
                b_cur = b_new;
                g_cur = g_new;
                len = half;
            }

            let b_final = b_cur[0];
            let g_final = g_cur[0];

            // Add combined commitment P to main MSM
            msm.add_msm(&combined_msm);

            // Add x_i^{-1} * L_i + x_i * R_i for each round
            for i in 0..k {
                let x = challenges[i];
                let x_inv: C::ScalarExt = Option::from(x.invert()).ok_or(Error::OpeningError)?;
                msm.append_term(x_inv, l_points[i].to_curve());
                msm.append_term(x, r_points[i].to_curve());
            }

            // Add (eval - a_final * b_final) * U to the MSM
            let u_scalar = combined_eval - a_final * b_final;
            msm.append_term(u_scalar, u.to_curve());

            // Add -a_final * G_final to the MSM
            msm.append_term(-a_final, g_final.to_curve());
        }

        Ok(GuardIPA::new(msm))
    }
}
