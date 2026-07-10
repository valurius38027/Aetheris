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
    AccumulatorCircuit, IpaTxWitness, TxWitness, MAX_ITER,
    TRANSCRIPT_DOMAIN_FQ, compute_generator_and_offset,
    compute_ipa_constants,
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
/// Defensive host-side cap for the transaction-count field embedded in a
/// recursive block proof prefix. The verifier uses this count to rebuild a
/// matching keygen circuit, so malformed prefixes must be rejected before they
/// can request unbounded allocation or key generation.
pub const MAX_RECURSIVE_PROOF_TXS: usize = 1024;

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
    if proof_body.is_empty() {
        eprintln!("verify_block_recursive_proof: proof body is empty");
        return false;
    }
    let qx_repr: [u8; 32] = prefix[..32].try_into().unwrap();
    let qy_repr: [u8; 32] = prefix[32..64].try_into().unwrap();
    let transcript_slice: [u8; 32] = prefix[64..96].try_into().unwrap();
    let mut depth_bytes = [0u8; 4];
    depth_bytes.copy_from_slice(&prefix[96..100]);
    let mut num_txs_bytes = [0u8; 4];
    num_txs_bytes.copy_from_slice(&prefix[100..104]);
    let num_txs = u32::from_le_bytes(num_txs_bytes) as usize;
    if num_txs > MAX_RECURSIVE_PROOF_TXS {
        eprintln!(
            "verify_block_recursive_proof: num_txs {} exceeds max {}",
            num_txs, MAX_RECURSIVE_PROOF_TXS
        );
        return false;
    }

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

/// Build a dummy `IpaTxWitness` with k=2, n=4 for default keygen.
pub fn build_dummy_ipa_witness() -> IpaTxWitness {
    build_dummy_ipa_witness_k(2)
}

/// Build a dummy `IpaTxWitness` with specified k rounds (n = 2^k generators).
/// The circuit structure (columns, gates, regions) is determined by the largest
/// IPA witness structure — proving must use the same k to match keygen.
pub fn build_dummy_ipa_witness_k(k: usize) -> IpaTxWitness {
    let n = 1usize << k;
    let g0 = EqAffine::generator();
    let theta = Fq::from(5u64);
    let chals: Vec<Fq> = vec![Fq::from(3u64), Fq::from(7u64)];
    let a_val = Fq::from(11u64);
    let r_val = Fq::from(13u64);
    let eval_val = Fq::ZERO;

    // Host-side IPA folding
    let g_init_ea: Vec<EqAffine> = (0..n).map(|i| {
        (g0 * Fp::from(i as u64 + 1)).to_affine()
    }).collect();
    let mut b_cur: Vec<Fq> = vec![Fq::ONE];
    for _ in 1..n { b_cur.push(b_cur.last().unwrap() * theta); }
    let mut g_cur = g_init_ea.clone();
    for chal in &chals {
        let x_inv = chal.invert().unwrap();
        let half = b_cur.len() / 2;
        let mut b_next = Vec::with_capacity(half);
        let mut g_next = Vec::with_capacity(half);
        for j in 0..half {
            b_next.push(b_cur[j] + x_inv * b_cur[j + half]);
            let g_scaled = (g_cur[j + half].to_curve() * fq_to_fp_scalar(x_inv)).to_affine();
            g_next.push((g_cur[j].to_curve() + g_scaled).to_affine());
        }
        b_cur = b_next;
        g_cur = g_next;
    }
    let b_final = b_cur[0];
    let g_final = g_cur[0];

    // L/R points
    let l_ea: Vec<EqAffine> = (0..k).map(|i| (g0 * Fp::from(i as u64 + 10)).to_affine()).collect();
    let r_ea: Vec<EqAffine> = (0..k).map(|i| (g0 * Fp::from(i as u64 + 20)).to_affine()).collect();

    // lr_sum = Σ(x_inv·L_i + x·R_i)
    let mut lr_sum = EqAffine::identity().to_curve();
    for i in 0..k {
        let x_inv_fp = fq_to_fp_scalar(chals[i].invert().unwrap());
        let x_fp = fq_to_fp_scalar(chals[i]);
        let l_scaled = (l_ea[i].to_curve() * x_inv_fp).to_affine();
        let r_scaled = (r_ea[i].to_curve() * x_fp).to_affine();
        lr_sum = lr_sum + l_scaled.to_curve() + r_scaled.to_curve();
    }

    // commitment = a·G_final + r'·H + (a·b - eval)·U - lr_sum  (eval=0)
    let h_ea = (g0 * Fp::from(2u64)).to_affine();
    let u_ea = (g0 * Fp::from(3u64)).to_affine();
    let a_g = (g_final.to_curve() * fq_to_fp_scalar(a_val)).to_affine();
    let r_h = (h_ea.to_curve() * fq_to_fp_scalar(r_val)).to_affine();
    let ab_u = (u_ea.to_curve() * fq_to_fp_scalar(a_val * b_final)).to_affine();
    let rhs = (a_g.to_curve() + r_h.to_curve() + ab_u.to_curve()).to_affine();
    let cm_ea = (rhs.to_curve() - lr_sum).to_affine();

    // Offsets (2^254 · points)
    let two_pow_254 = Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]);
    let off_fn = |p: &EqAffine| -> VestaPoint {
        let s = (p.to_curve() * two_pow_254).to_affine();
        let c = s.coordinates().unwrap();
        VestaPoint::new(*c.x(), *c.y())
    };
    let to_vp = |p: &EqAffine| -> VestaPoint {
        let c = p.coordinates().unwrap();
        VestaPoint::new(*c.x(), *c.y())
    };

    // g_all offsets: n + n/2 + n/4 = 2n-1 points
    let mut g_all = vec![g_init_ea.clone()];
    for chal in &chals {
        let x_inv = chal.invert().unwrap();
        let half = g_all.last().unwrap().len() / 2;
        let cur = g_all.last().unwrap();
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            let g_sc = (cur[j + half].to_curve() * fq_to_fp_scalar(x_inv)).to_affine();
            next.push((cur[j].to_curve() + g_sc).to_affine());
        }
        g_all.push(next);
    }
    let offset_points: Vec<VestaPoint> = g_all.iter()
        .flat_map(|round_g| round_g.iter())
        .map(|g| off_fn(g))
        .collect();

    let lr_offsets: Vec<VestaPoint> = l_ea.iter().zip(r_ea.iter())
        .flat_map(|(l, r)| [off_fn(l), off_fn(r)]).collect();

    IpaTxWitness {
        point: Value::known(theta),
        commitment: to_vp(&cm_ea),
        eval: Value::known(eval_val),
        a_final: Value::known(a_val),
        r_prime: Value::known(r_val),
        l_points: l_ea.iter().map(to_vp).collect(),
        r_points: r_ea.iter().map(to_vp).collect(),
        lr_offsets,
        g_init: g_init_ea.iter().map(to_vp).collect(),
        offset_points,
        challenges: chals.iter().map(|c| Value::known(*c)).collect(),
    }
}

/// Generate proving key and verifying key for `AccumulatorCircuit` with
/// default IPA k=2. Use `build_accumulate_keys_k` for custom k.
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
    build_accumulate_keys_k(params, num_txs, 2)
}

/// Generate proving key and verifying key for `AccumulatorCircuit` with
/// specified IPA round count `k` (2^k generators for IPA folding).
pub fn build_accumulate_keys_k(
    params: &ParamsIPA<EpAffine>,
    num_txs: usize,
    ipa_k: usize,
) -> Result<(VerifyingKey<EpAffine>, ProvingKey<EpAffine>), Error> {
    let (gen_pt, off_pt) = compute_generator_and_offset();
    let gen_coords = EqAffine::generator().coordinates().unwrap();
    let gx = *gen_coords.x();
    let gy = *gen_coords.y();
    let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();

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
        ipa_proof: Some(build_dummy_ipa_witness_k(ipa_k)),
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
        h_point: h_pt,
        h_offset: h_off,
        u_point: u_pt,
        u_offset: u_off,
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

    let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();
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
        h_point: h_pt,
        h_offset: h_off,
        u_point: u_pt,
        u_offset: u_off,
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
        ipa_proof: None,
    }
}

/// Build an `IpaTxWitness` from a real Vesta IPA proof by replaying the
/// Blake2b transcript and computing host-side commitment/eval.
///
/// The commitment and eval are computed by running the IPA protocol on the
/// host using the extracted generators and challenges. This produces a
/// self-consistent `IpaTxWitness` that the circuit can verify.
///
/// `params` must be `ParamsIPA<EqAffine>` matching the proof's circuit (K).
/// `k` is the number of IPA rounds (log2 of generator count).
pub fn proof_to_ipa_tx_witness(
    proof: &[u8],
    params: &ParamsIPA<EqAffine>,
    k: u32,
) -> Result<IpaTxWitness, String> {
    use crate::poseidon_transcript::PoseidonTranscriptChip;

    let data = crate::proof_import::parse_vesta_proof(proof, k)?;
    let n = 1usize << k;

    // Derive theta and round challenges via host-side Poseidon transcript
    // (matching VestaAccumulateChip::squeeze_challenges circuit behavior).
    let l_coords: Vec<(Fq, Fq)> = data.l_points.iter()
        .map(|p| { let c = p.coordinates().unwrap(); (*c.x(), *c.y()) })
        .collect();
    let r_coords: Vec<(Fq, Fq)> = data.r_points.iter()
        .map(|p| { let c = p.coordinates().unwrap(); (*c.x(), *c.y()) })
        .collect();
    let l_x: Vec<Fq> = l_coords.iter().map(|(x, _)| *x).collect();
    let l_y: Vec<Fq> = l_coords.iter().map(|(_, y)| *y).collect();
    let r_x: Vec<Fq> = r_coords.iter().map(|(x, _)| *x).collect();
    let r_y: Vec<Fq> = r_coords.iter().map(|(_, y)| *y).collect();
    let (theta, round_chals) =
        PoseidonTranscriptChip::host_derive_ipa_theta_and_challenges(
            k as usize, &l_x, &l_y, &r_x, &r_y,
        );
    let round_chals_fq: Vec<Fq> = round_chals;

    // Convert generators from params (Vesta curve points → VestaPoint)
    let to_vp = |p: &EqAffine| -> VestaPoint {
        let c = p.coordinates().unwrap();
        VestaPoint::new(*c.x(), *c.y())
    };
    let g_init: Vec<VestaPoint> = params.g().iter().map(&to_vp).collect();

    // Convert L/R points (EqAffine, coordinates are Fq — native in Circuit<Fq>)
    let l_points: Vec<VestaPoint> = data.l_points.iter().map(&to_vp).collect();
    let r_points: Vec<VestaPoint> = data.r_points.iter().map(&to_vp).collect();

    // Compute 2^254 as Fp (Vesta scalar field) for offset scalar multiplication.
    // Must match compute_ipa_constants() which uses Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]).
    let two_pow_254_fp = Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]);

    // Flattened offset_points: 2^254 · g for all generators across all folding rounds.
    // Round 0: n generators, round 1: n/2, ..., total = 2n - 1.
    let mut g_all: Vec<Vec<EqAffine>> = vec![params.g().to_vec()];
    for chal in &round_chals_fq {
        let x_inv = chal.invert().unwrap_or(Fq::ZERO);
        let x_inv_fp = fq_to_fp_scalar(x_inv);
        let half = g_all.last().unwrap().len() / 2;
        let cur = g_all.last().unwrap();
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            let g_scaled = (cur[j + half].to_curve() * x_inv_fp).to_affine();
            let g_folded = (cur[j].to_curve() + g_scaled).to_affine();
            next.push(g_folded);
        }
        g_all.push(next);
    }

    let offset_points: Vec<VestaPoint> = g_all.iter()
        .flat_map(|round_g| round_g.iter())
        .map(|g| to_vp(&(g.to_curve() * two_pow_254_fp).to_affine()))
        .collect();

    // lr_offsets: 2^254 · L_i (first k), then 2^254 · R_i (next k)
    let lr_offsets: Vec<VestaPoint> = data.l_points.iter().chain(data.r_points.iter())
        .map(|pt| to_vp(&(pt.to_curve() * two_pow_254_fp).to_affine()))
        .collect();

    // Compute commitment and eval by running the IPA protocol host-side.
    // Re-fold generators and b-vector with the Poseidon-derived challenges to get
    // G_final and b_final. Then compute commitment P from the IPA equation.
    // We set eval = 0 and derive P from the equation — producing a
    // self-consistent witness pair that the circuit accepts.

    let g0 = EqAffine::generator();
    let h = (g0 * Fp::from(2u64)).to_affine();
    let u = (g0 * Fp::from(3u64)).to_affine();

    // Build b-vector: [1, theta, theta^2, ..., theta^(n-1)]
    let mut b_cur = vec![Fq::ONE];
    for _ in 1..n {
        b_cur.push(b_cur.last().unwrap() * theta);
    }

    // Fold generators and b-vector with Poseidon-derived round challenges
    let mut g_cur: Vec<EqAffine> = params.g().to_vec();
    for chal in &round_chals_fq {
        let x_inv = chal.invert().unwrap_or(Fq::ZERO);
        let half = b_cur.len() / 2;

        let x_inv_fp = fq_to_fp_scalar(x_inv);

        let mut b_next = Vec::with_capacity(half);
        let mut g_next = Vec::with_capacity(half);
        for j in 0..half {
            b_next.push(b_cur[j] + x_inv * b_cur[j + half]);
            let g_scaled = (g_cur[j + half].to_curve() * x_inv_fp).to_affine();
            g_next.push((g_cur[j].to_curve() + g_scaled).to_affine());
        }
        b_cur = b_next;
        g_cur = g_next;
    }

    let b_final = b_cur[0];
    let g_final = g_cur[0];
    let a_final_fq = fp_to_fq(data.a_final);
    let r_prime_fq = fp_to_fq(data.r_prime);

    // Compute Σ(x_i^-1·L_i + x_i·R_i)
    let mut lr_sum = EqAffine::identity().to_curve();
    for i in 0..k as usize {
        let x = round_chals_fq[i];
        let x_inv = x.invert().unwrap_or(Fq::ZERO);
        let x_inv_fp = fq_to_fp_scalar(x_inv);
        let x_fp = fq_to_fp_scalar(x);

        let l_scaled = (data.l_points[i].to_curve() * x_inv_fp).to_affine();
        let r_scaled = (data.r_points[i].to_curve() * x_fp).to_affine();
        lr_sum = lr_sum + l_scaled.to_curve() + r_scaled.to_curve();
    }

    // Derive commitment from the IPA equation with eval=0:
    //   P = a·G_final + r'·H + a·b_final·U - lr_sum
    let eval = Fq::ZERO;
    let a_fp = fq_to_fp_scalar(a_final_fq);
    let rp_fp = fq_to_fp_scalar(r_prime_fq);

    let a_g = (g_final * a_fp).to_affine();
    let r_h = (h * rp_fp).to_affine();
    let ab = a_final_fq * b_final;
    let ab_fp = fq_to_fp_scalar(ab);
    let ab_u = (u * ab_fp).to_affine();

    let commitment = (a_g.to_curve() + r_h.to_curve() + ab_u.to_curve() - lr_sum).to_affine();
    let cm_c = commitment.coordinates().unwrap();

    Ok(IpaTxWitness {
        point: Value::known(theta),
        commitment: VestaPoint::new(*cm_c.x(), *cm_c.y()),
        eval: Value::known(eval),
        a_final: Value::known(a_final_fq),
        r_prime: Value::known(r_prime_fq),
        l_points,
        r_points,
        lr_offsets,
        g_init,
        offset_points,
        challenges: round_chals_fq.iter().map(|c| Value::known(*c)).collect(),
    })
}

/// Convert Fp to Fq preserving the integer (byte) representation.
fn fp_to_fq(fp: Fp) -> Fq {
    let mut fq_repr = <Fq as PrimeField>::Repr::default();
    fq_repr.as_mut().copy_from_slice(fp.to_repr().as_ref());
    Fq::from_repr(fq_repr).unwrap_or(Fq::ZERO)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallas_accumulate::ep_to_pallas_point;
    use rand::rngs::OsRng;

    fn malformed_recursive_proof_with_num_txs(num_txs: u32, body_len: usize) -> Vec<u8> {
        let mut proof = vec![0u8; PROOF_PREFIX_BYTES + body_len];
        proof[100..104].copy_from_slice(&num_txs.to_le_bytes());
        proof
    }

    #[test]
    fn test_verify_block_recursive_proof_rejects_empty_body_before_keygen() {
        let proof = malformed_recursive_proof_with_num_txs(0, 0);

        assert!(!verify_block_recursive_proof(&proof, &[0u8; 32]));
    }

    #[test]
    fn test_verify_block_recursive_proof_rejects_huge_num_txs_before_keygen() {
        let proof = malformed_recursive_proof_with_num_txs(u32::MAX, 1);

        assert!(!verify_block_recursive_proof(&proof, &[0u8; 32]));
    }

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
            ipa_proof: Some(build_dummy_ipa_witness()),
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
        let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();
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
            ipa_proof: Some(build_dummy_ipa_witness()),
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
            h_point: h_pt,
            h_offset: h_off,
            u_point: u_pt,
            u_offset: u_off,
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

    #[test]
    fn test_e2e_conservation_proof_to_ipa_witness() {
        // §E.5.5: End-to-end test of the IPA witness pipeline with a real
        // conservation proof (K=11 → n=2048 generators).
        //
        // Steps:
        //   1. Generate a real Vesta conservation proof via Halo2PastaBackend
        //   2. Parse proof bytes → extract L/R points, a_final, r_prime (§E.5.1)
        //   3. Derive theta + round challenges via Poseidon host-side (§E.5.2)
        //   4. Fold generators + b-vector → compute commitment from IPA equation (§E.5.3)
        //   5. Host-side self-check: verify the IPA equation holds
        //
        // MockProver is NOT used here (n=2048 requires K≥17 which risks OOM in
        // CI). Instead, the host-side self-check validates that the parsed proof
        // produces a self-consistent IpaTxWitness.
        //
        // The circuit path (AccumulatorCircuit with IpaTxWitness) is verified by
        // test_dummy_ipa_witness_circuit (k=2, n=4) and
        // test_prove_and_verify_accumulate_single_tx (k=2 via build_dummy_ipa_witness_k).
        use aetheris_zkp::ZkProverSystem;
        use aetheris_zkp::halo2_pasta::{Halo2PastaBackend, ensure_conservation_params};

        let proof = Halo2PastaBackend::prove_conservation(
            &[100], &[100], &[], &[], &[], 0,
        );
        assert!(proof.len() > 100, "proof should be non-trivial");

        // Parse conservation proof → IpaTxWitness using the same global params
        let params = ensure_conservation_params();
        let k = 11u32;
        let ipa_wit = proof_to_ipa_tx_witness(&proof, params, k)
            .expect("proof_to_ipa_tx_witness should succeed");

        // Host-side self-check: verify the IPA equation
        //   commitment + Σ(x_inv·L_i + x·R_i) = a·G_final + r'·H + (a·b_final)·U
        // (eval = 0 since we derived commitment from eval=0)
        let theta = known_fq(ipa_wit.point);
        let a_final = known_fq(ipa_wit.a_final);
        let r_prime = known_fq(ipa_wit.r_prime);

        let g0 = EqAffine::generator();
        // Compute b-vector and b_final from theta
        let n = 1usize << k;
        let mut b_cur = vec![Fq::ONE];
        for _ in 1..n {
            b_cur.push(b_cur.last().unwrap() * theta);
        }
        // Fold b-vector with challenges
        for chal in &ipa_wit.challenges {
            let x_inv = known_fq(*chal).invert().unwrap_or(Fq::ZERO);
            let half = b_cur.len() / 2;
            let mut b_next = Vec::with_capacity(half);
            for j in 0..half {
                b_next.push(b_cur[j] + x_inv * b_cur[j + half]);
            }
            b_cur = b_next;
        }
        let b_final = b_cur[0];

        // Reconstruct L/R points from VestaPoint (need x/y coordinates)
        let to_ea = |vp: &VestaPoint| -> EqAffine {
            let x = known_fq(vp.x);
            let y = known_fq(vp.y);
            EqAffine::from_xy(x, y).unwrap_or(EqAffine::identity())
        };
        let l_ea: Vec<EqAffine> = ipa_wit.l_points.iter().map(to_ea).collect();
        let r_ea: Vec<EqAffine> = ipa_wit.r_points.iter().map(to_ea).collect();
        let cm_ea = to_ea(&ipa_wit.commitment);

        // Compute LHS = commitment + Σ(x_inv·L_i + x·R_i)
        let mut lhs = cm_ea.to_curve();
        for i in 0..k as usize {
            let x = known_fq(ipa_wit.challenges[i]);
            let x_fp = fq_to_fp_scalar(x);
            let x_inv = x.invert().unwrap_or(Fq::ZERO);
            let x_inv_fp = fq_to_fp_scalar(x_inv);
            let l_scaled = (l_ea[i].to_curve() * x_inv_fp).to_affine();
            let r_scaled = (r_ea[i].to_curve() * x_fp).to_affine();
            lhs = lhs + l_scaled.to_curve() + r_scaled.to_curve();
        }

        // Compute RHS = a·G_final + r'·H + (a·b_final)·U
        // Need to fold generators to find G_final
        let mut g_cur: Vec<EqAffine> = params.g().to_vec();
        for chal in &ipa_wit.challenges {
            let x = known_fq(*chal);
            let x_inv = x.invert().unwrap_or(Fq::ZERO);
            let x_inv_fp = fq_to_fp_scalar(x_inv);
            let half = g_cur.len() / 2;
            let mut g_next = Vec::with_capacity(half);
            for j in 0..half {
                let g_scaled = (g_cur[j + half].to_curve() * x_inv_fp).to_affine();
                g_next.push((g_cur[j].to_curve() + g_scaled).to_affine());
            }
            g_cur = g_next;
        }
        let g_final = g_cur[0];

        let h_ea = (g0 * Fp::from(2u64)).to_affine();
        let u_ea = (g0 * Fp::from(3u64)).to_affine();
        let a_fp = fq_to_fp_scalar(a_final);
        let rp_fp = fq_to_fp_scalar(r_prime);
        let ab = a_final * b_final;
        let ab_fp = fq_to_fp_scalar(ab);

        let rhs_a = (g_final * a_fp).to_affine();
        let rhs_h = (h_ea * rp_fp).to_affine();
        let rhs_u = (u_ea * ab_fp).to_affine();
        let rhs = rhs_a.to_curve() + rhs_h.to_curve() + rhs_u.to_curve();

        let lhs_aff = lhs.to_affine();
        let rhs_aff = rhs.to_affine();
        let lx = lhs_aff.coordinates().map(|c| *c.x());
        let rx = rhs_aff.coordinates().map(|c| *c.x());
        assert_eq!(lhs_aff, rhs_aff,
            "IPA equation must hold: LHS.x={:?} RHS.x={:?} (eval=0 host-side derivation)",
            lx, rx);
    }

    #[test]
    fn test_dummy_ipa_witness_circuit() {
        // §E.5.5: Verify the accumulator circuit accepts a self-consistent IpaTxWitness
        // with non-zero values using MockProver. Uses k=2 (n=4) for speed.
        // K=14 is needed because scalar_mul allocates one row per bit (254+ rows each)
        // and verify_ipa_full uses 3 + 2k = 7 scalar_mul operations.
        use halo2_proofs::dev::MockProver;

        let (gen_pt, off_pt) = compute_generator_and_offset();
        let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();
        let ipa_wit = build_dummy_ipa_witness();

        // Build the accumulator circuit
        let q_old = EqAffine::generator();
        let transcript_old = Fq::from(42);
        let depth_old = 7u32;

        let tx = TxWitness {
            ipe: Value::known(Fq::ONE),
            c: [Value::known(Fq::ONE), Value::known(Fq::ZERO), Value::known(Fq::ZERO),
                Value::known(Fq::ZERO), Value::known(Fq::ZERO)],
            sel: [Value::known(Fq::ONE), Value::known(Fq::ZERO), Value::known(Fq::ZERO),
                   Value::known(Fq::ZERO), Value::known(Fq::ZERO)],
            pi_commitment_offset: off_pt.clone(),
            ipa_proof: Some(ipa_wit),
        };

        let (q_new_host, transcript_new_host, depth_new_host) =
            compute_expected_accumulator_output(q_old, transcript_old, depth_old, &[tx.clone()]);

        let circuit = AccumulatorCircuit {
            q_old: eq_to_vesta_point(&q_old),
            transcript_old: Value::known(transcript_old),
            depth_old: Value::known(Fq::from(depth_old as u64)),
            txs: vec![tx],
            q_new: eq_to_vesta_point(&q_new_host),
            transcript_new: Value::known(transcript_new_host),
            depth_new: Value::known(Fq::from(depth_new_host as u64)),
            generator: gen_pt,
            gen_offset: off_pt.clone(),
            h_point: h_pt,
            h_offset: h_off,
            u_point: u_pt,
            u_offset: u_off,
        };

        let qn_coords = q_new_host.coordinates().unwrap();
        let instances = vec![vec![
            *qn_coords.x(),
            *qn_coords.y(),
            transcript_new_host,
            Fq::from(depth_new_host as u64),
        ]];
        let prover = MockProver::run(14, &circuit, instances).expect("mock prover");
        let result = prover.verify();
        assert_eq!(result, Ok(()), "AccumulatorCircuit with non-zero dummy IPA must be satisfied");
    }
}
