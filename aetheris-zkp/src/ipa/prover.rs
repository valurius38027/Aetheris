use std::io;

use halo2_backend::poly::commitment::{Params, Prover as ProverTrait};
use halo2_backend::poly::query::ProverQuery;
use halo2_backend::transcript::{ChallengeScalar, EncodedChallenge, TranscriptWrite};
use halo2_middleware::zal::traits::MsmAccel;
use halo2_proofs::arithmetic::{CurveExt, Field};
use halo2_proofs::halo2curves::group::Curve as GroupCurve;
use halo2_proofs::halo2curves::CurveAffine;
use rand_core::RngCore;

use crate::ipa::commitment::{ParamsIPA, ThetaChallenge, RoundChallenge};

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
        _rng: R,
        transcript: &mut T,
        queries: I,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = ProverQuery<'com, C>> + Clone,
        R: RngCore,
    {
        let params = self.params;
        let all_queries: Vec<ProverQuery<'com, C>> = queries.into_iter().collect();
        let mut seen = std::collections::BTreeSet::new();
        let unique_points: Vec<&ProverQuery<'com, C>> = all_queries
            .iter()
            .filter(|q| seen.insert(q.point))
            .collect();

        for &first_q in &unique_points {
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

            let mut combined = vec![C::ScalarExt::ZERO; n];
            let mut pow = C::ScalarExt::ONE;
            for q in point_queries.iter() {
                for (c, pv) in combined.iter_mut().zip(q.poly.values.iter()) {
                    *c += pow * *pv;
                }
                pow = pow * theta_val;
            }

            let mut b = vec![C::ScalarExt::ONE; n];
            for i in 1..n {
                b[i] = b[i - 1] * point;
            }

            let g = params.g();
            let u_aff = *params.u();
            let u_proj = u_aff.to_curve();

            let mut a_cur = combined;
            let mut b_cur = b;
            let mut g_cur: Vec<C> = g.to_vec();
            let mut len = n;
            while len > 1 {
                let half = len / 2;
                let (a_lo, a_hi) = a_cur.split_at(half);
                let (b_lo, b_hi) = b_cur.split_at(half);
                let (g_lo, g_hi) = g_cur.split_at(half);

                let c_l = inner_product(a_lo, b_hi);
                let c_r = inner_product(a_hi, b_lo);

                let l_msm = engine.msm(a_lo, g_hi);
                let l_proj = l_msm + u_proj * c_l;
                transcript.write_point(l_proj.to_affine())?;

                let r_msm = engine.msm(a_hi, g_lo);
                let r_proj = r_msm + u_proj * c_r;
                transcript.write_point(r_proj.to_affine())?;

                let x: ChallengeScalar<C, RoundChallenge> =
                    transcript.squeeze_challenge_scalar();
                let x_val = *x;
                let x_inv: C::ScalarExt = Option::from(x_val.invert()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "IPA prover: zero challenge in round")
                })?;

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

            transcript.write_scalar(a_cur[0])?;
        }

        Ok(())
    }
}
