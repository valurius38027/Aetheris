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

// ── Host precomputation ──
//
// These functions transform an IpaProofWitness into the PallasPoint and witness
// data required by RecursiveProofCircuit.  They are the host-side counterparts
// of the #[cfg(test)] helpers in pallas_ipa / pallas_accumulate / recursive_proof.

use core::array;

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::Value,
    halo2curves::pasta::Fp,
};
use halo2curves::CurveAffine;

use crate::{
    Limb,
    non_native_fp::{FpElement, FP_NUM_LIMBS},
    pallas_ecc::PallasPoint,
};

/// Big-endian: `0x00...020...0` where the `1` bit is at position 85.
fn big_limb_base() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
}

fn big_to_fq(big: &num_bigint::BigUint) -> Fq {
    let bytes = big.to_bytes_le();
    let mut repr = <Fq as PrimeField>::Repr::default();
    let len = bytes.len().min(repr.as_ref().len());
    repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
    <Fq as PrimeField>::from_repr(repr).unwrap()
}

/// Convert an EpAffine (Pallas) point to a PallasPoint (3-limb Fp-over-Fq).
pub fn ep_to_pallas_point(p: &EpAffine) -> PallasPoint {
    let coords = p.coordinates().unwrap();
    let x_fp = *coords.x();
    let y_fp = *coords.y();
    let lbb = big_limb_base();
    let x_big = num_bigint::BigUint::from_bytes_le(x_fp.to_repr().as_ref());
    let y_big = num_bigint::BigUint::from_bytes_le(y_fp.to_repr().as_ref());
    let x_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
        let lv = (&x_big / &lbb.pow(i as u32)) % &lbb;
        Limb { value: Value::known(big_to_fq(&lv)), cell: None }
    });
    let y_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
        let lv = (&y_big / &lbb.pow(i as u32)) % &lbb;
        Limb { value: Value::known(big_to_fq(&lv)), cell: None }
    });
    PallasPoint {
        x: FpElement { limbs: x_limbs },
        y: FpElement { limbs: y_limbs },
        x_cell: None,
        y_cell: None,
    }
}

/// Host-side Fp point addition witness: returns (λ, rx, ry) as FpElements.
pub fn fp_add_witness(p: &PallasPoint, q: &PallasPoint) -> (FpElement, FpElement, FpElement) {
    let reconstruct = |el: &FpElement| -> Fp {
        let mut big = num_bigint::BigUint::from(0u32);
        let base = big_limb_base();
        for (i, limb) in el.limbs.iter().enumerate() {
            if let Ok(val) = limb.value.assign() {
                let lv_big = num_bigint::BigUint::from_bytes_le(val.to_repr().as_ref());
                big += lv_big * base.pow(i as u32);
            }
        }
        let mut repr = <Fp as PrimeField>::Repr::default();
        let le = big.to_bytes_le();
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        <Fp as PrimeField>::from_repr(repr).unwrap()
    };
    let px = reconstruct(&p.x);
    let py = reconstruct(&p.y);
    let qx = reconstruct(&q.x);
    let qy = reconstruct(&q.y);

    let lam = (qy - py) * (qx - px).invert().unwrap();
    let rx = lam.square() - px - qx;
    let ry = lam * (px - rx) - py;

    let fp_to_el = |fp: Fp| -> FpElement {
        let big = num_bigint::BigUint::from_bytes_le(fp.to_repr().as_ref());
        let base = big_limb_base();
        let limbs = array::from_fn(|i| {
            let lv = (&big / &base.pow(i as u32)) % &base;
            Limb { value: Value::known(big_to_fq(&lv)), cell: None }
        });
        FpElement { limbs }
    };

    (fp_to_el(lam), fp_to_el(rx), fp_to_el(ry))
}

/// Extract the 6 commitment limb values as `Fq` for the instance column.
pub fn commitment_limbs(p: &PallasPoint) -> Vec<Fq> {
    let mut limbs = Vec::with_capacity(2 * FP_NUM_LIMBS);
    for limb in &p.x.limbs {
        limbs.push(limb.value.assign().unwrap_or(Fq::ZERO));
    }
    for limb in &p.y.limbs {
        limbs.push(limb.value.assign().unwrap_or(Fq::ZERO));
    }
    limbs
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
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
        let wit_lr = fp_add_witness(&p_l, &p_r);
        let wit_accum = fp_add_witness(&p_com, &p_sum_lr);

        let rhs_gh_curve = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
        let p_rhs_gh = ep_to_pallas_point(&rhs_gh_curve);
        let wit_gh = fp_add_witness(&p_a, &p_rh);
        let wit_u = fp_add_witness(&p_rhs_gh, &p_ab);

        let circuit = RecursiveProofCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_witnesses: vec![wit_lr, wit_accum],
            rhs_witnesses: vec![wit_gh, wit_u],
        };

        // Keygen.
        let params = ParamsIPA::<EpAffine>::setup(16, &mut OsRng, "test_recursive");
        let (vk, pk) = build_recursive_keys(&params).expect("keygen failed");

        // Prove.
        let pub_limbs = vec![commitment_limbs(&circuit.commitment)];
        let proof = prove_recursive(&params, &pk, circuit, pub_limbs).expect("prove_recursive failed");
        assert!(!proof.is_empty(), "proof must not be empty");

        // Verify with correct public inputs (reconstruct commitment from original curve points).
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
        let pub_limbs_verify = commitment_limbs(&ep_to_pallas_point(&commitment_pt_verify));
        let valid = verify_recursive_proof(&params, &vk, &proof, vec![pub_limbs_verify]);
        assert!(valid, "verify_recursive_proof must accept valid proof");

        // Corrupt the proof — verification must fail.
        let p_com_corrupt = ep_to_pallas_point(&commitment_pt);
        let mut corrupted = proof.clone();
        corrupted[proof.len() / 2] ^= 0xff;
        let rejected = verify_recursive_proof(&params, &vk, &corrupted, vec![commitment_limbs(&p_com_corrupt)]);
        assert!(!rejected, "verify must reject corrupted proof");
    }
}
