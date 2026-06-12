//! Recursive proof production and verification.
//!
//! Bridges `RecursiveProofCircuit` (Phase 1.13) with the Halo2 IPA proof
//! pipeline from `aetheris-zkp`, enabling real recursive SNARK production.

use halo2_backend::plonk::verifier::verify_proof_with_strategy;
use halo2_backend::poly::VerificationStrategy;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};

use aetheris_zkp::ipa::commitment::{CommitmentSchemeIPA, ParamsIPA};
use aetheris_zkp::ipa::prover::ProverIPA;
use aetheris_zkp::ipa::strategy::SingleStrategyIPA;

use crate::pallas_accumulate::commitment_limbs;
use crate::recursive_proof::RecursiveProofCircuit;

/// Generate a proving key and verifying key for the recursive proof circuit.
pub fn build_recursive_keys(
    params: &ParamsIPA<EpAffine>,
) -> Result<(VerifyingKey<EpAffine>, ProvingKey<EpAffine>), Error> {
    let circuit = RecursiveProofCircuit::default();
    let vk = keygen_vk(params, &circuit)?;
    let pk = keygen_pk(params, vk.clone(), &circuit)?;
    Ok((vk, pk))
}

/// Produce a recursive SNARK from a `RecursiveProofCircuit`.
pub fn prove_recursive(
    params: &ParamsIPA<EpAffine>,
    pk: &ProvingKey<EpAffine>,
    circuit: RecursiveProofCircuit,
    instances: Vec<Vec<Fq>>,
) -> Result<Vec<u8>, Error> {
    let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
    create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[instances],
        rand::rngs::OsRng,
        &mut transcript,
    )?;
    Ok(transcript.finalize())
}

/// Verify a recursive SNARK.
pub fn verify_recursive_proof(
    params: &ParamsIPA<EpAffine>,
    vk: &VerifyingKey<EpAffine>,
    proof: &[u8],
    instances: Vec<Vec<Fq>>,
) -> bool {
    let mut transcript = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(proof);
    match verify_proof_with_strategy::<
        CommitmentSchemeIPA<EpAffine>,
        _,
        Challenge255<EpAffine>,
        Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>,
        SingleStrategyIPA<'_, EpAffine>,
    >(
        params,
        vk,
        SingleStrategyIPA::new(params),
        &[instances],
        &mut transcript,
    ) {
        Ok(strategy) => strategy.finalize(),
        Err(_) => false,
    }
}

/// Build public instance vector: 6 commitment limbs + 1 state_root Fq.
pub fn build_recursive_instance(
    commitment: &crate::pallas_ecc::PallasPoint,
    state_root: &[u8; 32],
) -> Vec<Fq> {
    let mut limbs = commitment_limbs(commitment);
    let mut repr = <Fq as ff::PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(state_root);
    let sr_fq = <Fq as ff::PrimeField>::from_repr(repr).unwrap();
    limbs.push(sr_fq);
    limbs
}

/// Verify a block's recursive proof against its state_root and accumulator state.
///
/// Extracts the IPA commitment from `accumulator_bytes`, builds the public
/// instance vector, and calls `verify_recursive_proof`. Regenerates params
/// and VK on every call — callers should cache these for production use.
pub fn verify_block_recursive_proof(
    proof: &[u8],
    state_root: &[u8; 32],
    accumulator_bytes: &[u8],
) -> bool {
    let params = aetheris_zkp::ipa::commitment::ParamsIPA::setup_deterministic(16);
    let acc = match crate::accumulator::AccumulatorIPA::from_bytes(accumulator_bytes) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pallas_point = crate::pallas_accumulate::ep_to_pallas_point(&acc.Q);
    let instances = vec![build_recursive_instance(&pallas_point, state_root)];
    let (vk, _pk) = match build_recursive_keys(&params) {
        Ok(k) => k,
        Err(_) => return false,
    };
    verify_recursive_proof(&params, &vk, proof, instances)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallas_accumulate::ep_to_pallas_point;
    use halo2_proofs::halo2curves::pasta::EpAffine;
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
    use rand::rngs::OsRng;

    #[test]
    fn test_prove_and_verify_recursive() {
        // Build synthetic test data (same pattern as recursive_proof tests).
        let g = EpAffine::generator();
        let h = (g.to_curve() * Fq::from(2u64)).to_affine();
        let u = (g.to_curve() * Fq::from(3u64)).to_affine();
        let g_final = g;

        let a_mul_g = (g_final.to_curve() * Fq::from(11u64)).to_affine();
        let r_prime_mul_h = (h.to_curve() * Fq::from(13u64)).to_affine();
        let ab_eval_mul_u = (u.to_curve() * Fq::from(17u64)).to_affine();
        let rhs_pt = (a_mul_g.to_curve() + r_prime_mul_h.to_curve() + ab_eval_mul_u.to_curve()).to_affine();

        let l_scaled = (g_final.to_curve() * Fq::from(2u64)).to_affine();
        let r_scaled = (h.to_curve() * Fq::from(3u64)).to_affine();
        let commitment_pt = (rhs_pt.to_curve() - l_scaled.to_curve() - r_scaled.to_curve()).to_affine();

        let p_com = ep_to_pallas_point(&commitment_pt);
        let p_l = ep_to_pallas_point(&l_scaled);
        let p_r = ep_to_pallas_point(&r_scaled);
        let p_a = ep_to_pallas_point(&a_mul_g);
        let p_rh = ep_to_pallas_point(&r_prime_mul_h);
        let p_ab = ep_to_pallas_point(&ab_eval_mul_u);

        let sum_lr_curve = (l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        let p_sum_lr = ep_to_pallas_point(&sum_lr_curve);
        let wit_lr = crate::pallas_accumulate::fp_add_witness(&p_l, &p_r);
        let wit_accum = crate::pallas_accumulate::fp_add_witness(&p_com, &p_sum_lr);

        let rhs_gh_curve = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
        let p_rhs_gh = ep_to_pallas_point(&rhs_gh_curve);
        let wit_gh = crate::pallas_accumulate::fp_add_witness(&p_a, &p_rh);
        let wit_u = crate::pallas_accumulate::fp_add_witness(&p_rhs_gh, &p_ab);

        // state_root must be < Fq modulus.
        let state_root_val: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 0xab; b };
        let circuit = RecursiveProofCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_witnesses: vec![wit_lr, wit_accum],
            rhs_witnesses: vec![wit_gh, wit_u],
            state_root: state_root_val,
        };

        // Keygen.
        let params = ParamsIPA::<EpAffine>::setup(16, &mut OsRng, "test_recursive");
        let (vk, pk) = build_recursive_keys(&params).expect("keygen failed");

        // Prove.
        let pub_limbs = vec![build_recursive_instance(&circuit.commitment, &state_root_val)];
        let proof = prove_recursive(&params, &pk, circuit, pub_limbs).expect("prove_recursive failed");
        assert!(!proof.is_empty(), "proof must not be empty");

        // Verify with correct public inputs.
        let commitment_pt_verify = {
            let g2 = EpAffine::generator();
            let h2 = (g2.to_curve() * Fq::from(2u64)).to_affine();
            let u2 = (g2.to_curve() * Fq::from(3u64)).to_affine();
            let a2 = (g2.to_curve() * Fq::from(11u64)).to_affine();
            let rh2 = (h2.to_curve() * Fq::from(13u64)).to_affine();
            let ab2 = (u2.to_curve() * Fq::from(17u64)).to_affine();
            let rhs2 = (a2.to_curve() + rh2.to_curve() + ab2.to_curve()).to_affine();
            let l2 = (g2.to_curve() * Fq::from(2u64)).to_affine();
            let r2 = (h2.to_curve() * Fq::from(3u64)).to_affine();
            (rhs2.to_curve() - l2.to_curve() - r2.to_curve()).to_affine()
        };
        let pub_limbs_verify = vec![build_recursive_instance(
            &ep_to_pallas_point(&commitment_pt_verify),
            &state_root_val,
        )];
        let valid = verify_recursive_proof(&params, &vk, &proof, pub_limbs_verify);
        assert!(valid, "verify_recursive_proof must accept valid proof");

        // Corrupt the proof — verification must fail.
        let mut corrupted = proof.clone();
        corrupted[proof.len() / 2] ^= 0xff;
        let rejected = verify_recursive_proof(
            &params,
            &vk,
            &corrupted,
            vec![build_recursive_instance(&ep_to_pallas_point(&commitment_pt), &state_root_val)],
        );
        assert!(!rejected, "verify must reject corrupted proof");
    }
}
