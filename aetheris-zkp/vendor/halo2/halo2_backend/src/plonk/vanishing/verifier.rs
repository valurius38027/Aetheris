use std::iter;

use halo2_middleware::ff::Field;

use crate::{
    arithmetic::CurveAffine,
    plonk::{ChallengeX, ChallengeY, Error, VerifyingKey},
    poly::{
        commitment::{ParamsVerifier, MSM},
        VerifierQuery,
    },
    transcript::{read_n_points, EncodedChallenge, TranscriptRead},
};

use super::Argument;

pub(in crate::plonk) struct Committed<C: CurveAffine> {
    random_poly_commitment: C,
}

pub(in crate::plonk) struct Constructed<C: CurveAffine> {
    h_commitments: Vec<C>,
    random_poly_commitment: C,
}

pub(in crate::plonk) struct PartiallyEvaluated<C: CurveAffine> {
    h_commitments: Vec<C>,
    random_poly_commitment: C,
    random_eval: C::Scalar,
    h_eval_from_transcript: C::Scalar,
}

pub(in crate::plonk) struct Evaluated<C: CurveAffine, M: MSM<C>> {
    h_commitment: M,
    random_poly_commitment: C,
    random_eval: C::Scalar,
    h_eval: C::Scalar,
}

impl<C: CurveAffine> Argument<C> {
    pub(in crate::plonk) fn read_commitments_before_y<
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    >(
        transcript: &mut T,
    ) -> Result<Committed<C>, Error> {
        let random_poly_commitment = transcript.read_point()?;

        Ok(Committed {
            random_poly_commitment,
        })
    }
}

impl<C: CurveAffine> Committed<C> {
    pub(in crate::plonk) fn read_commitments_after_y<
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    >(
        self,
        vk: &VerifyingKey<C>,
        transcript: &mut T,
    ) -> Result<Constructed<C>, Error> {
        // Obtain a commitment to h(X) in the form of multiple pieces of degree n - 1
        let h_commitments = read_n_points(transcript, vk.domain.get_quotient_poly_degree())?;

        Ok(Constructed {
            h_commitments,
            random_poly_commitment: self.random_poly_commitment,
        })
    }
}

impl<C: CurveAffine> Constructed<C> {
    pub(in crate::plonk) fn evaluate_after_x<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        self,
        transcript: &mut T,
    ) -> Result<PartiallyEvaluated<C>, Error> {
        let random_eval = transcript.read_scalar()?;
        let h_eval_from_transcript = transcript.read_scalar()?;

        Ok(PartiallyEvaluated {
            h_commitments: self.h_commitments,
            random_poly_commitment: self.random_poly_commitment,
            random_eval,
            h_eval_from_transcript,
        })
    }
}

impl<C: CurveAffine> PartiallyEvaluated<C> {
    pub(in crate::plonk) fn verify<'params, P: ParamsVerifier<'params, C>>(
        self,
        params: &'params P,
        expressions: impl Iterator<Item = C::Scalar>,
        y: ChallengeY<C>,
        xn: C::Scalar,
    ) -> Result<Evaluated<C, P::MSM>, Error> {
        let expr_vec: Vec<C::Scalar> = expressions.collect();
        if crate::diagnostics::dbg_enabled() {
            for (i, v) in expr_vec.iter().enumerate() {
                eprintln!("[VERIFIER-EXPR] idx={} val={:?}", i, v);
            }
            eprintln!("[VERIFIER] num_expressions={} xn={:?} y={:?}", expr_vec.len(), xn, *y);
        }
        let h_eval_from_transcript = self.h_eval_from_transcript;
        if crate::diagnostics::dbg_enabled() {
            eprintln!("[VERIFIER] h_eval_from_transcript={:?}", h_eval_from_transcript);
        }
        let expected_fx_no_div = expr_vec.iter().fold(C::Scalar::ZERO, |h_eval, v| h_eval * *y + v);
        let expected_h_eval = expected_fx_no_div * ((xn - C::Scalar::ONE).invert().unwrap());
        if crate::diagnostics::dbg_enabled() {
            eprintln!("[VERIFIER-DETAIL] expected_h_eval={:?} expected_fx={:?}", expected_h_eval, expected_fx_no_div);
        }

        let h_commitment =
            self.h_commitments
                .iter()
                .rev()
                .fold(params.empty_msm(), |mut acc, commitment| {
                    acc.scale(xn);
                    let commitment: C::CurveExt = (*commitment).into();
                    acc.append_term(C::Scalar::ONE, commitment);

                    acc
                });

        let fx_verifier = expected_h_eval * (xn - C::Scalar::ONE);
        if crate::diagnostics::dbg_enabled() {
            let prover_fx = self.h_eval_from_transcript * (xn - C::Scalar::ONE);
            eprintln!("[VERIFIER] expected_h_eval={:?} transcript_h_eval={:?} fx_verifier={:?} prover_fx={:?} xn={:?} match={}",
                expected_h_eval, self.h_eval_from_transcript, fx_verifier, prover_fx, xn,
                expected_h_eval == self.h_eval_from_transcript);
            eprintln!("[VERIFIER] fx_match={}",
                fx_verifier == prover_fx);
        }

        if expected_h_eval != self.h_eval_from_transcript {
            return Err(Error::ConstraintSystemFailure);
        }

        Ok(Evaluated {
            h_commitment,
            random_poly_commitment: self.random_poly_commitment,
            random_eval: self.random_eval,
            h_eval: expected_h_eval,
        })
    }
}

impl<C: CurveAffine, M: MSM<C>> Evaluated<C, M> {
    pub(in crate::plonk) fn queries(
        &self,
        x: ChallengeX<C>,
    ) -> impl Iterator<Item = VerifierQuery<'_, C, M>> + Clone {
        iter::empty()
            .chain(Some(VerifierQuery::new_msm(
                &self.h_commitment,
                *x,
                self.h_eval,
            )))
            .chain(Some(VerifierQuery::new_commitment(
                &self.random_poly_commitment,
                *x,
                self.random_eval,
            )))
    }
}
