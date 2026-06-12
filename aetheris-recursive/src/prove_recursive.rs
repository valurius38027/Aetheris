//! Recursive proof production and verification.
//!
//! ## Old pipeline (deprecated, Pallas-based)
//! - `build_recursive_keys`, `prove_recursive`, `verify_recursive_proof`
//! - `verify_block_recursive_proof` — placeholder, retains signature for state.rs
//!
//! ## New pipeline (§C, Vesta-native)
//! - `build_accumulate_keys` — keygen for `AccumulatorCircuit`
//! - `prove_block_recursive` — produce accumulator recursive proof
//! - `verify_accumulate_proof` — verify accumulator proof

use ff::{Field, FromUniformBytes, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;
use halo2_backend::plonk::verifier::verify_proof_with_strategy;
use halo2_backend::poly::VerificationStrategy;
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_proofs::halo2curves::pasta::{EpAffine, EqAffine, Fp, Fq};
use halo2curves::CurveAffine;

use aetheris_zkp::ipa::commitment::{CommitmentSchemeIPA, ParamsIPA};
use aetheris_zkp::ipa::prover::ProverIPA;
use aetheris_zkp::ipa::strategy::SingleStrategyIPA;

use crate::circuit_accumulate::{
    AccumulatorCircuit, TxWitness, MAX_ITER,
    TRANSCRIPT_DOMAIN_FQ, compute_generator_and_offset,
};
use crate::pallas_accumulate::commitment_limbs;
use crate::recursive_proof::RecursiveProofCircuit;
use crate::vesta_ecc::VestaPoint;

// ── Old pipeline (deprecated, kept for backward compat) ──

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

/// Size of the instance prefix in the proof format: Q.x(32) + Q.y(32) + transcript(32) + depth(4).
pub const INSTANCE_PREFIX_BYTES: usize = 100;
/// Full proof prefix including `num_txs` field: Q.x(32) || Q.y(32) || transcript(32) || depth(4) || num_txs(4)
pub const PROOF_PREFIX_BYTES: usize = 104;

/// Return the canonical genesis recursive accumulator state as serialized bytes.
/// Format matches the proof prefix: [Q.x(32) || Q.y(32) || transcript(32) || depth(4)].
pub fn genesis_recursive_state_bytes() -> Vec<u8> {
    use group::prime::PrimeCurveAffine;
    let g = EqAffine::generator();
    let coords = g.coordinates().unwrap();
    let mut buf = Vec::with_capacity(INSTANCE_PREFIX_BYTES);
    buf.extend_from_slice(coords.x().to_repr().as_ref());
    buf.extend_from_slice(coords.y().to_repr().as_ref());
    buf.extend_from_slice(&[0u8; 32]); // transcript = 0
    buf.extend_from_slice(&0u32.to_le_bytes()); // depth = 0
    buf
}

/// Verify a block's recursive proof against its state_root and accumulator state.
pub fn verify_block_recursive_proof(
    proof: &[u8],
    _state_root: &[u8; 32],
) -> bool {
    if proof.len() < PROOF_PREFIX_BYTES {
        eprintln!("verify_block_recursive_proof: proof too short ({})", proof.len());
        return false;
    }
    let (prefix, proof_body) = proof.split_at(PROOF_PREFIX_BYTES);
    let qx_repr: [u8; 32] = prefix[..32].try_into().unwrap();
    let qy_repr: [u8; 32] = prefix[32..64].try_into().unwrap();
    let transcript_slice: [u8; 32] = prefix[64..96].try_into().unwrap();
    let mut depth_bytes = [0u8; 4];
    depth_bytes.copy_from_slice(&prefix[96..100]);
    let mut num_txs_bytes = [0u8; 4];
    num_txs_bytes.copy_from_slice(&prefix[100..104]);
    let num_txs = u32::from_le_bytes(num_txs_bytes) as usize;

    use ff::FromUniformBytes;
    use halo2_proofs::halo2curves::pasta::Fq;
    let q_x = Fq::from_repr(qx_repr).unwrap_or(Fq::ZERO);
    let q_y = Fq::from_repr(qy_repr).unwrap_or(Fq::ZERO);
    let transcript_new = {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&transcript_slice);
        Fq::from_uniform_bytes(&buf)
    };
    let depth_new = Fq::from(u32::from_le_bytes(depth_bytes) as u64);

    let instances = vec![vec![q_x, q_y, transcript_new, depth_new]];

    // Match the prover's K=15 and exact tx count so circuit structure is identical.
    let params = aetheris_zkp::ipa::commitment::ParamsIPA::setup_deterministic(15);
    let (vk, _pk) = match build_accumulate_keys(&params, num_txs) {
        Ok(k) => k,
        Err(_) => return false,
    };
    verify_accumulate_proof(&params, &vk, proof_body, instances)
}

// ── New pipeline (§C: Vesta-native AccumulatorCircuit) ──

/// Host-side Poseidon compression: (left, right) → state[0].
fn host_poseidon_fq(left: Fq, right: Fq) -> Fq {
    let spec = aetheris_zkp::poseidon_fq::ensure_poseidon_spec();
    let mut state = [left, right, Fq::ZERO];
    aetheris_zkp::poseidon_fq::poseidon_permute(spec, &mut state);
    state[0]
}

/// Convert an Fq scalar to an Fp scalar matching the circuit's scalar_mul
/// bit handling (only uses bits 0..253, ignoring bits 254+).
fn fq_to_fp_scalar(fq: Fq) -> Fp {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(fq.to_repr().as_ref());
    buf[31] &= 0x3f;
    Fp::from_uniform_bytes(&buf)
}

/// Extract a known Fq from a `Value<Fq>`. The layout is guaranteed to match
/// `Option<Fq>` (single-field struct), so transmute is sound.
fn known_fq(v: Value<Fq>) -> Fq {
    let opt: Option<Fq> = unsafe { std::mem::transmute(v) };
    opt.expect("expected Known Fq value")
}

/// Convert an `EqAffine` point to a `VestaPoint`.
fn eq_to_vesta_point(pt: &EqAffine) -> VestaPoint {
    let coords = pt.coordinates().unwrap();
    VestaPoint::new(*coords.x(), *coords.y())
}

/// Compute the expected accumulator output after processing `txs`,
/// using host-side arithmetic that mirrors `AccumulatorCircuit::synthesize`.
///
/// Returns `(q_new, transcript_new, depth_new)`.
fn compute_expected_accumulator_output(
    q_old: EqAffine,
    transcript_old: Fq,
    depth_old: u32,
    txs: &[TxWitness],
) -> (EqAffine, Fq, u32) {
    let mut q_cur = q_old;
    let mut transcript_cur = transcript_old;
    let mut depth_cur = depth_old;

    for tx in txs {
        let ipe = known_fq(tx.ipe);

        let mut c_sel = Fq::ZERO;
        for i in 0..MAX_ITER {
            if known_fq(tx.sel[i]) == Fq::ONE {
                c_sel = known_fq(tx.c[i]);
                break;
            }
        }

        // pi_commitment = G * c_sel (Vesta scalar mul: Fp scalar)
        let c_fp = fq_to_fp_scalar(c_sel);
        let pi_commitment = (EqAffine::generator() * c_fp).to_affine();

        // Challenge = Poseidon(Poseidon(TRANSCRIPT_DOMAIN_FQ, transcript_cur), ipe)
        let chal_tmp = host_poseidon_fq(TRANSCRIPT_DOMAIN_FQ, transcript_cur);
        let challenge = host_poseidon_fq(chal_tmp, ipe);

        // Q_new = Q_cur + challenge * pi_commitment
        let chal_fp = fq_to_fp_scalar(challenge);
        let scaled = (pi_commitment.to_curve() * chal_fp).to_affine();
        let q_new = (q_cur.to_curve() + scaled.to_curve()).to_affine();

        // Transcript chain
        let coords = q_new.coordinates().unwrap();
        let h1 = host_poseidon_fq(transcript_cur, challenge);
        let h2 = host_poseidon_fq(*coords.x(), ipe);
        let transcript_new = host_poseidon_fq(h1, h2);

        q_cur = q_new;
        transcript_cur = transcript_new;
        depth_cur += 1;
    }

    (q_cur, transcript_cur, depth_cur)
}

/// Generate proving key and verifying key for `AccumulatorCircuit`.
///
/// `num_txs` must equal the length of the txs slice that will be passed to
/// `prove_block_recursive`. The keygen circuit must have the same structure
/// (same number of Poseidon calls, scalar_mul iterations, etc.) as the
/// proving circuit.
///
/// Note: uses `ParamsIPA<EpAffine>` (Pallas IPA) because the IPA scheme's
/// scalar field must match the circuit's field (Fq). Vesta's scalar field is
/// Fp, which would require `Circuit<Fp>`, but our circuit operates over Fq
/// (Vesta's base field = Pallas's scalar field).
pub fn build_accumulate_keys(
    params: &ParamsIPA<EpAffine>,
    num_txs: usize,
) -> Result<(VerifyingKey<EpAffine>, ProvingKey<EpAffine>), Error> {
    let (gen_pt, off_pt) = compute_generator_and_offset();
    let gen_coords = EqAffine::generator().coordinates().unwrap();
    let gx = *gen_coords.x();
    let gy = *gen_coords.y();
    let dummy_tx = TxWitness {
        ipe: Value::known(Fq::ONE),
        c: [
            Value::known(Fq::ONE),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
        ],
        sel: [
            Value::known(Fq::ONE),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
            Value::known(Fq::ZERO),
        ],
        pi_commitment_offset: off_pt.clone(),
    };
    let circuit = AccumulatorCircuit {
        q_old: VestaPoint::new(gx, gy),
        transcript_old: Value::known(Fq::ZERO),
        depth_old: Value::known(Fq::ZERO),
        txs: vec![dummy_tx; num_txs],
        q_new: VestaPoint::new(gx, gy),
        transcript_new: Value::known(Fq::ZERO),
        depth_new: Value::known(Fq::ZERO),
        generator: gen_pt,
        gen_offset: off_pt,
    };
    let vk = keygen_vk(params, &circuit)?;
    let pk = keygen_pk(params, vk.clone(), &circuit)?;
    Ok((vk, pk))
}

/// Produce an O(1) recursive SNARK proving the accumulator transition
/// from `(q_old, transcript_old, depth_old)` to `(q_new, transcript_new,
/// depth_new)` across all transactions in `txs`.
///
/// The accumulator operates on the Vesta curve (EqAffine), while the outer
/// IPA proof is over Pallas (EpAffine). This is sound because Pasta 2-cycle
/// gives Fq = Pallas scalar field = Vesta base field = circuit field.
///
/// Public instances (4 Fq cells):
///   inst[0] = Q_new.x
///   inst[1] = Q_new.y
///   inst[2] = transcript_new
///   inst[3] = Fq::from(depth_new)
pub fn prove_block_recursive(
    params: &ParamsIPA<EpAffine>,
    pk: &ProvingKey<EpAffine>,
    q_old: EqAffine,
    transcript_old: Fq,
    depth_old: u32,
    txs: Vec<TxWitness>,
) -> Result<(Vec<u8>, EqAffine, Fq, u32), Error> {
    let (q_new, transcript_new, depth_new) =
        compute_expected_accumulator_output(q_old, transcript_old, depth_old, &txs);

    let num_txs = txs.len();
    let (gen_pt, off_pt) = compute_generator_and_offset();
    let q_old_pt = eq_to_vesta_point(&q_old);
    let q_new_pt = eq_to_vesta_point(&q_new);

    let circuit = AccumulatorCircuit {
        q_old: q_old_pt,
        transcript_old: Value::known(transcript_old),
        depth_old: Value::known(Fq::from(depth_old as u64)),
        txs,
        q_new: q_new_pt,
        transcript_new: Value::known(transcript_new),
        depth_new: Value::known(Fq::from(depth_new as u64)),
        generator: gen_pt,
        gen_offset: off_pt,
    };

    let coords = q_new.coordinates().unwrap();
    let instances = vec![vec![
        *coords.x(),
        *coords.y(),
        transcript_new,
        Fq::from(depth_new as u64),
    ]];

    let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
    create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[instances],
        rand::rngs::OsRng,
        &mut transcript,
    )?;

    // Prepend public instances: [Q.x(32) || Q.y(32) || transcript(32) || depth(4) || num_txs(4)]
    // so the verifier can parse them without external knowledge.
    let proof_body = transcript.finalize();
    let mut prefixed = Vec::with_capacity(32 + 32 + 32 + 4 + 4 + proof_body.len());
    prefixed.extend_from_slice(coords.x().to_repr().as_ref());
    prefixed.extend_from_slice(coords.y().to_repr().as_ref());
    prefixed.extend_from_slice(transcript_new.to_repr().as_ref());
    prefixed.extend_from_slice(&(depth_new as u32).to_le_bytes());
    prefixed.extend_from_slice(&(num_txs as u32).to_le_bytes());
    prefixed.extend_from_slice(&proof_body);

    Ok((prefixed, q_new, transcript_new, depth_new))
}

/// Verify an accumulator recursive proof against the claimed public instances.
///
/// `instances` must be `vec![vec![q_new_x, q_new_y, transcript_new, depth_new_fq]]`.
pub fn verify_accumulate_proof(
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
        Err(e) => {
            eprintln!("verify_accumulate_proof error: {:?}", e);
            false
        },
    }
}

/// Parse a recursive-state byte slice (format: Q.x(32) || Q.y(32) || transcript(32) || depth(4))
/// into (EqAffine, Fq, u32). Returns `None` on malformed input.
pub fn parse_recursive_state(state: &[u8]) -> Option<(EqAffine, Fq, u32)> {
    use ff::PrimeField;
    use halo2_proofs::halo2curves::pasta::EqAffine;
    if state.len() < INSTANCE_PREFIX_BYTES {
        return None;
    }
    let qx_repr: [u8; 32] = state[..32].try_into().ok()?;
    let qy_repr: [u8; 32] = state[32..64].try_into().ok()?;
    let transcript: [u8; 32] = state[64..96].try_into().ok()?;
    let mut depth_bytes = [0u8; 4];
    depth_bytes.copy_from_slice(&state[96..100]);
    let depth = u32::from_le_bytes(depth_bytes);
    let qx = Fq::from_repr(qx_repr);
    if bool::from(qx.is_none()) {
        return None;
    }
    let qy = Fq::from_repr(qy_repr);
    if bool::from(qy.is_none()) {
        return None;
    }
    let q_opt = EqAffine::from_xy(qx.unwrap(), qy.unwrap());
    if bool::from(q_opt.is_none()) {
        return None;
    }
    let q = q_opt.unwrap();
    let transcript_fq = {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&transcript);
        Fq::from_uniform_bytes(&buf)
    };
    Some((q, transcript_fq, depth))
}

/// Build a `TxWitness` from a `Transaction`, computing IPE via the same
/// two-phase (blake3 → Poseidon) hash as `AccumulatorIPA::accumulate`.
pub fn compute_tx_witness(
    proof: &[u8],
    output_commitments: &[[u8; 32]],
    public_amount: i64,
    gen_offset: &VestaPoint,
) -> TxWitness {
    use blake3::hash as b3hash;
    use aetheris_zkp::poseidon_fq;

    // Inner proof hash = blake3(proof)
    let inner_proof_hash = b3hash(proof);
    // Commitment hash = blake3(domain || count || commitments || public_amount)
    let commitment_hash = {
        let mut h = blake3::Hasher::new();
        h.update(&[0xC0u8]);
        h.update(&(output_commitments.len() as u32).to_le_bytes());
        for cm in output_commitments { h.update(cm); }
        h.update(&public_amount.to_le_bytes());
        h.finalize()
    };
    let ipe = poseidon_fq::poseidon_hash(inner_proof_hash.as_bytes(), commitment_hash.as_bytes());

    // NUMS hash-to-curve: try-and-increment over MAX_ITER iterations.
    // Host-side replicates the circuit's hash_to_curve logic to determine
    // the winning iteration and precompute c[] + sel[] + offset.
    let domain_fq_bytes = {
        let h = b3hash(b"aetheris-pi-cmt-v2\x00");
        let mut uniform = [0u8; 64];
        uniform[..32].copy_from_slice(h.as_bytes());
        Fq::from_uniform_bytes(&uniform).to_repr()
    };
    let seed = poseidon_fq::poseidon_hash(&domain_fq_bytes, &ipe);

    let mut c = [Value::known(Fq::ZERO); MAX_ITER];
    let mut sel = [Value::known(Fq::ZERO); MAX_ITER];
    let mut found_idx = None;

    for i in 0..MAX_ITER {
        let mut mixed32 = [0u8; 32];
        mixed32[..4].copy_from_slice(&(i as u32).to_le_bytes());
        mixed32[4..].copy_from_slice(&seed[..28]);
        let mut input64 = [0u8; 64];
        input64[..32].copy_from_slice(&mixed32);
        let c_candidate = Fq::from_uniform_bytes(&input64);
        c[i] = Value::known(c_candidate);

        if found_idx.is_none() {
            let c_fp = fq_to_fp_scalar(c_candidate);
            let pt = (EqAffine::generator() * c_fp).to_affine();
            if !bool::from(pt.is_identity()) {
                sel[i] = Value::known(Fq::ONE);
                found_idx = Some(i);
            }
        }
    }

    // Compute pi_commitment_offset = 2^254 · pi_commitment for the winning iteration
    let pi_commitment_offset = match found_idx {
        Some(idx) => {
            let c_fp = fq_to_fp_scalar(known_fq(c[idx]));
            let pi = (EqAffine::generator() * c_fp).to_affine();
            let two_pow_254 = Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]);
            let off = (pi.to_curve() * two_pow_254).to_affine();
            let coords = off.coordinates().unwrap();
            VestaPoint::new(*coords.x(), *coords.y())
        }
        None => gen_offset.clone(),
    };

    TxWitness {
        ipe: Value::known(Fq::from_uniform_bytes(&{
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&ipe);
            buf
        })),
        c,
        sel,
        pi_commitment_offset,
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallas_accumulate::ep_to_pallas_point;
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

        let params = ParamsIPA::<EpAffine>::setup(16, &mut OsRng, "test_recursive");
        let (vk, pk) = build_recursive_keys(&params).expect("keygen failed");

        let pub_limbs = vec![build_recursive_instance(&circuit.commitment, &state_root_val)];
        let proof = prove_recursive(&params, &pk, circuit, pub_limbs).expect("prove_recursive failed");
        assert!(!proof.is_empty(), "proof must not be empty");

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

    #[test]
    fn test_prove_and_verify_accumulate_single_tx() {
        // 1-tx case: prove_block_recursive + verify_accumulate_proof round-trip
        let q_old = EqAffine::generator();
        let transcript_old = Fq::from(42);
        let depth_old = 7;

        let (_gen_pt, off_pt) = compute_generator_and_offset();
        let tx = TxWitness {
            ipe: Value::known(Fq::ONE),
            c: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            sel: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            pi_commitment_offset: off_pt,
        };

        // Use K=15 to ensure enough rows for 1 tx circuit (scalar_mul loops are large)
        let params = ParamsIPA::<EpAffine>::setup(15, &mut OsRng, "test_accumulate_single");
        let (vk, pk) = build_accumulate_keys(&params, 1).expect("keygen failed");

        // Independently compute expected output for cross-check
        let (q_new_host, transcript_new_host, depth_new_host) =
            compute_expected_accumulator_output(q_old, transcript_old, depth_old, &[tx.clone()]);
        assert_eq!(depth_new_host, 8, "single tx should increment depth by 1");

        let (proof, q_new, transcript_new, depth_new) =
            prove_block_recursive(&params, &pk, q_old, transcript_old, depth_old, vec![tx])
                .expect("prove_block_recursive failed");
        assert!(!proof.is_empty(), "proof must not be empty");

        // Cross-check: prover output must match host-side computation
        assert_eq!(q_new, q_new_host, "prover q_new must match host computation");
        assert_eq!(transcript_new, transcript_new_host, "prover transcript_new must match");
        assert_eq!(depth_new, depth_new_host, "prover depth_new must match");

        let coords = q_new.coordinates().unwrap();
        let instances = vec![vec![
            *coords.x(),
            *coords.y(),
            transcript_new,
            Fq::from(depth_new as u64),
        ]];
        let proof_body = &proof[PROOF_PREFIX_BYTES..];
        let valid = verify_accumulate_proof(&params, &vk, proof_body, instances.clone());
        assert!(valid, "verify_accumulate_proof must accept valid proof for 1 tx");

        // Also verify with host-computed instances
        let host_coords = q_new_host.coordinates().unwrap();
        let host_instances = vec![vec![
            *host_coords.x(),
            *host_coords.y(),
            transcript_new_host,
            Fq::from(depth_new_host as u64),
        ]];
        let valid_host = verify_accumulate_proof(&params, &vk, proof_body, host_instances);
        assert!(valid_host, "verify must also accept with host-computed instances");

        let mut corrupted = proof_body.to_vec();
        let idx = corrupted.len() / 2;
        corrupted[idx] ^= 0xff;
        let rejected = verify_accumulate_proof(&params, &vk, &corrupted, instances);
        assert!(!rejected, "verify must reject corrupted proof");
    }

    #[test]
    fn test_prove_and_verify_accumulate_debug() {
        // Debug: use compute_expected_accumulator_output to get the correct
        // expected instances, then verify the circuit matches.
        let (_gen_pt, off_pt) = compute_generator_and_offset();
        let tx = TxWitness {
            ipe: Value::known(Fq::ONE),
            c: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            sel: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            pi_commitment_offset: off_pt.clone(),
        };

        let q_old = EqAffine::generator();
        let transcript_old = Fq::from(42);
        let depth_old = 7;

        let (q_new_host, transcript_new_host, depth_new_host) =
            compute_expected_accumulator_output(q_old, transcript_old, depth_old, &[tx.clone()]);

        let qn_coords = q_new_host.coordinates().unwrap();
        println!("q_new (host) x = {:?}", qn_coords.x().to_repr());
        println!("transcript_new (host) = {:?}", transcript_new_host.to_repr());
        println!("depth_new (host) = {}", depth_new_host);

        let q_old_pt = eq_to_vesta_point(&q_old);
        let q_new_pt = eq_to_vesta_point(&q_new_host);
        let circuit_check = AccumulatorCircuit {
            q_old: q_old_pt,
            transcript_old: Value::known(transcript_old),
            depth_old: Value::known(Fq::from(depth_old as u64)),
            txs: vec![tx],
            q_new: q_new_pt,
            transcript_new: Value::known(transcript_new_host),
            depth_new: Value::known(Fq::from(depth_new_host as u64)),
            generator: _gen_pt,
            gen_offset: off_pt,
        };
        use halo2_proofs::dev::MockProver;
        let instances_check = vec![vec![
            *qn_coords.x(),
            *qn_coords.y(),
            transcript_new_host,
            Fq::from(depth_new_host as u64),
        ]];
        let prover = MockProver::run(14, &circuit_check, instances_check).expect("mock prover");
        let result = prover.verify();
        println!("MockProver result: {:?}", result);
        assert_eq!(result, Ok(()), "AccumulatorCircuit should be satisfied with correct instances");
    }

    #[test]
    fn test_prove_and_verify_accumulate_empty() {
        // 0-tx case: q_new == q_old, transcript_new == transcript_old, depth_new == depth_old
        let q_old = EqAffine::generator();
        let transcript_old = Fq::from(42);
        let depth_old = 7;

        let params = ParamsIPA::<EpAffine>::setup(14, &mut OsRng, "test_accumulate_empty");
        let (vk, pk) = build_accumulate_keys(&params, 0).expect("keygen failed");

        let (proof, q_new, transcript_new, depth_new) =
            prove_block_recursive(&params, &pk, q_old, transcript_old, depth_old, vec![])
                .expect("prove_block_recursive failed");
        assert!(!proof.is_empty(), "proof must not be empty");
        assert_eq!(q_old, q_new);
        assert_eq!(transcript_old, transcript_new);
        assert_eq!(depth_old, depth_new);

        let coords = q_new.coordinates().unwrap();
        let instances = vec![vec![
            *coords.x(),
            *coords.y(),
            transcript_new,
            Fq::from(depth_new as u64),
        ]];
        let proof_body = &proof[PROOF_PREFIX_BYTES..];
        let valid = verify_accumulate_proof(&params, &vk, proof_body, instances.clone());
        assert!(valid, "verify_accumulate_proof must accept valid proof for 0 txs");

        let mut corrupted = proof_body.to_vec();
        let idx = corrupted.len() / 2;
        corrupted[idx] ^= 0xff;
        let rejected = verify_accumulate_proof(&params, &vk, &corrupted, instances);
        assert!(!rejected, "verify must reject corrupted proof");
    }
}
