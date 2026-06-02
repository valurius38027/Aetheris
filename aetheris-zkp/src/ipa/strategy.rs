use halo2_backend::poly::commitment::{CommitmentScheme, MSM, Verifier};
use halo2_backend::poly::VerificationStrategy;
use halo2_backend::plonk::Error;
use halo2_middleware::zal::impls::H2cEngine;
use halo2_proofs::arithmetic::{CurveExt, Field};
use halo2_proofs::halo2curves::CurveAffine;
use rand_core::OsRng;

use crate::ipa::commitment::{
    CommitmentSchemeIPA, MSMIPA, ParamsIPA,
};
use crate::ipa::verifier::VerifierIPA;

/// A verifier that checks a single IPA proof.
#[derive(Clone, Debug)]
pub struct SingleStrategyIPA<'params, C: CurveAffine>
where
    C::CurveExt: CurveExt,
{
    msm: MSMIPA<C>,
    params: &'params ParamsIPA<C>,
}

impl<'params, C: CurveAffine> SingleStrategyIPA<'params, C>
where
    C::CurveExt: CurveExt,
{
    /// Constructs an empty single-proof verifier.
    pub fn new(params: &'params ParamsIPA<C>) -> Self {
        SingleStrategyIPA {
            msm: MSMIPA::new(),
            params,
        }
    }
}

impl<'params, C> VerificationStrategy<'params, CommitmentSchemeIPA<C>, VerifierIPA<C>>
    for SingleStrategyIPA<'params, C>
where
    C: CurveAffine,
    C::CurveExt: CurveExt,
{
    fn new(
        params: &'params <CommitmentSchemeIPA<C> as CommitmentScheme>::ParamsVerifier,
    ) -> Self {
        SingleStrategyIPA::new(params)
    }

    fn process(
        self,
        f: impl FnOnce(
            <VerifierIPA<C> as Verifier<'params, CommitmentSchemeIPA<C>>>::MSMAccumulator,
        ) -> Result<
            <VerifierIPA<C> as Verifier<'params, CommitmentSchemeIPA<C>>>::Guard,
            Error,
        >,
    ) -> Result<Self, Error> {
        let guard = f(self.msm)?;
        let msm = guard.msm_accumulator;
        Ok(SingleStrategyIPA {
            msm,
            params: self.params,
        })
    }

    fn finalize(self) -> bool {
        let default_engine = H2cEngine::new();
        self.msm.check(&default_engine)
    }
}

/// A verifier that checks multiple IPA proofs in a batch.
///
/// Each proof's MSM accumulator is randomized by a random scalar before
/// being combined, enabling secure batch verification.
#[derive(Clone, Debug)]
pub struct AccumulatorStrategyIPA<'params, C: CurveAffine>
where
    C::CurveExt: CurveExt,
{
    msm_accumulator: MSMIPA<C>,
    params: &'params ParamsIPA<C>,
}

impl<'params, C: CurveAffine> AccumulatorStrategyIPA<'params, C>
where
    C::CurveExt: CurveExt,
{
    /// Constructs an empty batch verifier.
    pub fn new(params: &'params ParamsIPA<C>) -> Self {
        AccumulatorStrategyIPA {
            msm_accumulator: MSMIPA::new(),
            params,
        }
    }

    /// Constructs a batch verifier with an already-initialized MSM accumulator.
    pub fn with(
        msm_accumulator: MSMIPA<C>,
        params: &'params ParamsIPA<C>,
    ) -> Self {
        AccumulatorStrategyIPA {
            msm_accumulator,
            params,
        }
    }
}

impl<'params, C> VerificationStrategy<'params, CommitmentSchemeIPA<C>, VerifierIPA<C>>
    for AccumulatorStrategyIPA<'params, C>
where
    C: CurveAffine,
    C::CurveExt: CurveExt,
{
    fn new(
        params: &'params <CommitmentSchemeIPA<C> as CommitmentScheme>::ParamsVerifier,
    ) -> Self {
        AccumulatorStrategyIPA::new(params)
    }

    fn process(
        mut self,
        f: impl FnOnce(
            <VerifierIPA<C> as Verifier<'params, CommitmentSchemeIPA<C>>>::MSMAccumulator,
        ) -> Result<
            <VerifierIPA<C> as Verifier<'params, CommitmentSchemeIPA<C>>>::Guard,
            Error,
        >,
    ) -> Result<Self, Error> {
        self.msm_accumulator
            .scale(C::ScalarExt::random(OsRng));

        let guard = f(self.msm_accumulator)?;
        Ok(AccumulatorStrategyIPA {
            msm_accumulator: guard.msm_accumulator,
            params: self.params,
        })
    }

    fn finalize(self) -> bool {
        let default_engine = H2cEngine::new();
        self.msm_accumulator.check(&default_engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipa::commitment::GuardIPA;
    use crate::ipa::prover::ProverIPA;
    use halo2_backend::poly::commitment::{Blind, Params, ParamsProver, Prover as ProverTrait};
    use halo2_backend::poly::query::{ProverQuery, VerifierQuery};
    use halo2_backend::poly::Coeff;
    use halo2_backend::poly::Polynomial;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::group::Curve as GroupCurve;
    use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, Transcript, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    };
    use rand_core::OsRng;

    fn make_test_poly(params: &ParamsIPA<EpAffine>) -> Polynomial<Fq, Coeff> {
        let poly_len = params.n() as usize;
        let mut poly = Polynomial::<Fq, Coeff>::new_empty(poly_len, Fq::ZERO);
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = Fq::from(i as u64 + 1);
        }
        poly
    }

    fn create_test_proof(
        params: &ParamsIPA<EpAffine>,
        engine: &H2cEngine,
        poly: &Polynomial<Fq, Coeff>,
    ) -> Vec<u8> {
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EpAffine, Challenge255<EpAffine>>::init(Vec::new());

        // Write commitment as common_point to simulate the real Halo2 flow where
        // the multi-open protocol writes all instance/advice commitments before
        // calling the prover. This ensures theta is bound to the commitment.
        let comm = params.commit(engine, poly, Blind(Fq::ZERO));
        transcript.common_point(comm.to_affine()).expect("common_point should succeed");

        let prover = ProverIPA::new(params);

        let query = ProverQuery::new(Fq::from(3u64), poly, Blind(Fq::ZERO));
        let queries = vec![query];

        prover
            .create_proof_with_engine(engine, OsRng, &mut transcript, queries)
            .expect("prover should succeed");

        transcript.finalize()
    }

    fn compute_eval(coeffs: &[Fq], point: Fq) -> Fq {
        let mut eval = Fq::ZERO;
        let mut pow = Fq::ONE;
        for &c in coeffs {
            eval += c * pow;
            pow *= point;
        }
        eval
    }

    #[test]
    fn test_single_strategy_new() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let _strategy = SingleStrategyIPA::new(&params);
    }

    #[test]
    fn test_accumulator_strategy_new() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let _strategy = AccumulatorStrategyIPA::new(&params);
    }

    #[test]
    fn test_single_strategy_process() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let strategy = SingleStrategyIPA::new(&params);

        let result = strategy.process(|msm| Ok(GuardIPA::new(msm)));
        assert!(result.is_ok());
        let strategy = result.unwrap();
        assert!(strategy.finalize());
    }

    #[test]
    fn test_accumulator_strategy_process() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let strategy = AccumulatorStrategyIPA::new(&params);

        let result = strategy.process(|msm| Ok(GuardIPA::new(msm)));
        assert!(result.is_ok());
        let strategy = result.unwrap();
        assert!(strategy.finalize());
    }

    #[test]
    fn test_accumulator_strategy_with() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let msm = MSMIPA::new();
        let strategy = AccumulatorStrategyIPA::with(msm, &params);
        let _ = strategy;
    }

    #[test]
    fn test_single_strategy_roundtrip() {
        let engine = H2cEngine::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let poly = make_test_poly(&params);
        let proof_bytes = create_test_proof(&params, &engine, &poly);

        let point = Fq::from(3u64);
        let comm = params.commit(&engine, &poly, Blind(Fq::ZERO));
        let comm_affine = comm.to_affine();
        let eval = compute_eval(&poly.values[..], point);

        let mut transcript =
            Blake2bRead::<&[u8], EpAffine, Challenge255<EpAffine>>::init(&proof_bytes[..]);

        // Write commitment as common_point to match the prover's transcript state
        transcript.common_point(comm_affine).expect("common_point should succeed");

        let strategy = SingleStrategyIPA::new(&params);
        let verifier = VerifierIPA::<EpAffine>::new();

        let query = VerifierQuery::new_commitment(&comm_affine, point, eval);
        let queries = vec![query];

        let result = strategy.process(|msm| {
            verifier
                .verify_proof(&mut transcript, queries, msm)
                .map_err(|_| Error::Opening)
        });

        assert!(result.is_ok(), "strategy process should succeed");
        let strategy = result.unwrap();
        assert!(strategy.finalize(), "proof verification should pass");
    }

    #[test]
    fn test_single_strategy_tampered_proof_rejected() {
        let engine = H2cEngine::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let poly = make_test_poly(&params);
        let mut proof_bytes = create_test_proof(&params, &engine, &poly);

        // tamper: flip a byte in the proof body
        if proof_bytes.len() > 10 {
            proof_bytes[5] ^= 0xFF;
        }

        let point = Fq::from(3u64);
        let comm = params.commit(&engine, &poly, Blind(Fq::ZERO));
        let comm_affine = comm.to_affine();
        let eval = compute_eval(&poly.values[..], point);

        let mut transcript =
            Blake2bRead::<&[u8], EpAffine, Challenge255<EpAffine>>::init(&proof_bytes[..]);

        // Write commitment as common_point to match the prover's transcript state
        transcript.common_point(comm_affine).expect("common_point should succeed");

        let strategy = SingleStrategyIPA::new(&params);
        let verifier = VerifierIPA::<EpAffine>::new();

        let query = VerifierQuery::new_commitment(&comm_affine, point, eval);
        let queries = vec![query];

        let result = strategy.process(|msm| {
            verifier
                .verify_proof(&mut transcript, queries, msm)
                .map_err(|_| Error::Opening)
        });

        match result {
            Ok(strategy) => {
                assert!(!strategy.finalize(), "tampered proof should be rejected");
            }
            Err(_) => {
                // tampering may cause transcript deserialization error -> also rejection
            }
        }
    }

    #[test]
    fn test_accumulator_strategy_roundtrip() {
        let engine = H2cEngine::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let poly = make_test_poly(&params);
        let proof_bytes = create_test_proof(&params, &engine, &poly);

        let point = Fq::from(3u64);
        let comm = params.commit(&engine, &poly, Blind(Fq::ZERO));
        let comm_affine = comm.to_affine();
        let eval = compute_eval(&poly.values[..], point);

        let mut transcript =
            Blake2bRead::<&[u8], EpAffine, Challenge255<EpAffine>>::init(&proof_bytes[..]);

        // Write commitment as common_point to match the prover's transcript state
        transcript.common_point(comm_affine).expect("common_point should succeed");

        let strategy = AccumulatorStrategyIPA::new(&params);
        let verifier = VerifierIPA::<EpAffine>::new();

        let query = VerifierQuery::new_commitment(&comm_affine, point, eval);
        let queries = vec![query];

        let result = strategy.process(|msm| {
            verifier
                .verify_proof(&mut transcript, queries, msm)
                .map_err(|_| Error::Opening)
        });

        assert!(result.is_ok(), "accumulator process should succeed");
        let strategy = result.unwrap();
        assert!(strategy.finalize(), "accumulator should verify the proof");
    }
}
