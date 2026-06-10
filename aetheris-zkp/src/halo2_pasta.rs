use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_middleware::ff::FromUniformBytes;
use halo2_backend::plonk::verifier::verify_proof_with_strategy;
use halo2_backend::poly::VerificationStrategy;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
        create_proof, keygen_pk, keygen_vk,
    },
    poly::{Rotation, commitment::Params},
    transcript::{
        Blake2bWrite, Blake2bRead, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};
use std::sync::OnceLock;
use std::fs;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadCore, aead::Aead};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::ipa::commitment::{CommitmentSchemeIPA, ParamsIPA};
use crate::ipa::prover::ProverIPA;
use crate::ipa::strategy::SingleStrategyIPA;
use crate::trait_::{ZkProverSystem, TxCommitments};
use crate::membership_circuit::MembershipCircuit;

const PROVING_K: u32 = 11;

static CACHED_PARAMS: OnceLock<ParamsIPA<EpAffine>> = OnceLock::new();
pub(crate) type CachedKeyPair = (
    halo2_proofs::plonk::VerifyingKey<EpAffine>,
    halo2_proofs::plonk::ProvingKey<EpAffine>,
);
static KEY_CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<(usize, usize), CachedKeyPair>>> =
    OnceLock::new();

pub(crate) fn ensure_params() -> &'static ParamsIPA<EpAffine> {
    CACHED_PARAMS.get_or_init(|| {
        let crs_paths = ["aetheris-zkp/crs.bin", "crs.bin"];
        for path in &crs_paths {
            if let Ok(data) = fs::read(path) {
                let mut cursor = std::io::Cursor::new(&data);
                if let Ok(params) = ParamsIPA::<EpAffine>::read(&mut cursor) {
                    eprintln!("[ZK] Loaded params from {} (k={})", path, params.k());
                    return params;
                }
            }
        }
        if cfg!(debug_assertions) {
            eprintln!("[ZK] WARNING: No params file found. Using deterministic IPA setup (DEV ONLY)");
            return ParamsIPA::<EpAffine>::setup(
                PROVING_K,
                &mut ChaCha20Rng::from_seed(*b"Aetheris IPA deterministic v0.00"),
                "value_conservation",
            );
        }
        panic!("[ZK] FATAL: No params file found. Place a params file or run in debug mode.");
    })
}

fn ensure_keys(
    amounts_in_len: usize,
    amounts_out_len: usize,
) -> (halo2_proofs::plonk::VerifyingKey<EpAffine>, halo2_proofs::plonk::ProvingKey<EpAffine>) {
    let params = ensure_params();
    let cache = KEY_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = (amounts_in_len, amounts_out_len);
    {
        let map = cache.lock().expect("key cache mutex poisoned");
        if let Some((vk, pk)) = map.get(&key) {
            return (vk.clone(), pk.clone());
        }
    }
    // Keygen circuit must satisfy net_value = total_in - total_out - public_amount = 0.
    // We use amounts_in = [1; n_in] (sum = n_in). The amounts_out vector sums to n_in whenever
    // n_out > 0; when n_out = 0, all input is "burned" into public_amount.
    // The amount values don't affect the constraint (only their sums), so any distribution works
    // as long as amounts_out sums to n_in. We fill at most n_in ones and pack the remainder
    // into the last filled slot (or slot 0 if n_in == 0).
    let (amounts_out, public_amount): (Vec<u64>, i64) = if amounts_out_len == 0 {
        // (n_in > 0, 0) case: burn all input as public_amount
        (vec![], amounts_in_len as i64)
    } else {
        let mut v = vec![0u64; amounts_out_len];
        let fill = amounts_in_len.min(amounts_out_len);
        for i in 0..fill {
            v[i] = 1;
        }
        if amounts_in_len > fill {
            // Pack remainder (n_in - fill) into the last filled slot.
            // This is safe because fill >= 1 whenever amounts_in_len > fill > 0.
            v[fill - 1] += (amounts_in_len - fill) as u64;
        }
        // Edge: n_in == 0 -> v stays all zeros, sum = 0 = n_in. ✓
        (v, 0)
    };
    let keygen_circuit = ValueConservationCircuit {
        amounts_in: vec![1u64; amounts_in_len],
        amounts_out,
        in_blindings: vec![[1u8; 32]; amounts_in_len],
        out_blindings: vec![[1u8; 32]; amounts_out_len],
        output_commitments: vec![vec![[1u8; 32]]; amounts_out_len],
        public_amount,
    };
    let vk = keygen_vk(params, &keygen_circuit).expect("keygen_vk failed");
    let pk = keygen_pk(params, vk.clone(), &keygen_circuit).expect("keygen_pk failed");
    let result = (vk.clone(), pk.clone());
    cache
        .lock()
        .expect("key cache mutex poisoned")
        .insert(key, (vk, pk));
    result
}

#[cfg(test)]
fn ensure_membership_keys(circuit: &MembershipCircuit) -> CachedKeyPair {
    let params = ensure_params();
    let vk = keygen_vk(params, circuit).expect("membership keygen_vk failed");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("membership keygen_pk failed");
    (vk, pk)
}

fn ensure_membership_keys_for_depth(depth: usize) -> CachedKeyPair {
    // After C-3 gate-based mux fix, VK is position_bits-independent.
    // The dummy circuit (all-false bits) produces a VK valid for any position_bits.
    let params = ensure_params();
    let dummy = MembershipCircuit::dummy(depth);
    let vk = keygen_vk(params, &dummy).expect("membership keygen_vk failed");
    let pk = keygen_pk(params, vk.clone(), &dummy).expect("membership keygen_pk failed");
    (vk, pk)
}

pub fn create_commitment(amount: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let amt_fq = Fq::from(amount);
    let h = blake3::hash(blinding);
    let mut uniform = [0u8; 64];
    uniform[..32].copy_from_slice(h.as_bytes());
    uniform[63] &= 0x3F;
    let blind_fq = Fq::from_uniform_bytes(&uniform);
    let commitment_fq = amt_fq + blind_fq;
    commitment_fq.to_repr()
}

pub fn create_nullifier(sk: &[u8], commitment_index: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(sk);
    hasher.update(&commitment_index.to_le_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Debug)]
pub struct ValueConfig {
    pub advice: [Column<Advice>; 5],
    pub s_running_sum: Selector,
    pub s_zero_check: Selector,
    pub s_conservation: Selector,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct ValueConservationCircuit {
    pub amounts_in: Vec<u64>,
    pub amounts_out: Vec<u64>,
    pub in_blindings: Vec<[u8; 32]>,
    pub out_blindings: Vec<[u8; 32]>,
    pub output_commitments: Vec<Vec<[u8; 32]>>,
    pub public_amount: i64,
}

impl ValueConservationCircuit {
    pub fn dummy() -> Self {
        Self {
            amounts_in: vec![],
            amounts_out: vec![],
            in_blindings: vec![],
            out_blindings: vec![],
            output_commitments: vec![],
            public_amount: 0,
        }
    }

    pub fn without_witnesses(&self) -> Self {
        Self::dummy()
    }
}

impl Circuit<Fq> for ValueConservationCircuit {
    type Config = ValueConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::dummy()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for col in &advice {
            meta.enable_equality(*col);
        }
        let s_running_sum = meta.selector();
        let s_zero_check = meta.selector();
        let s_conservation = meta.selector();
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        meta.create_gate("running_sum", |meta| {
            let s = meta.query_selector(s_running_sum);
            let z_prev = meta.query_advice(advice[0], Rotation(-1));
            let z_cur = meta.query_advice(advice[0], Rotation(0));
            let bit = meta.query_advice(advice[1], Rotation(0));
            vec![s * (z_prev - Expression::Constant(Fq::from(2)) * z_cur - bit)]
        });

        meta.create_gate("bit_constraint", |meta| {
            let s = meta.query_selector(s_running_sum);
            let b = meta.query_advice(advice[1], Rotation(0));
            vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
        });

        meta.create_gate("zero_check", |meta| {
            let s = meta.query_selector(s_zero_check);
            let a = meta.query_advice(advice[0], Rotation(0));
            let b = meta.query_advice(advice[2], Rotation(0));
            vec![s.clone() * (a - b.clone()), s * b]
        });

        meta.create_gate("conservation_running_sum", |meta| {
            let s = meta.query_selector(s_conservation);
            let prev = meta.query_advice(advice[2], Rotation(-1));
            let cur = meta.query_advice(advice[2], Rotation(0));
            let signed = meta.query_advice(advice[4], Rotation(0));
            vec![s * (cur - prev - signed)]
        });

        ValueConfig {
            advice,
            s_running_sum,
            s_zero_check,
            s_conservation,
            instance,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
        let all_amounts: Vec<u64> = self.amounts_in.iter()
            .chain(self.amounts_out.iter())
            .copied()
            .collect();

        layouter.assign_region(|| "value_conservation", |mut region| {
            let mut offset = 0;
            let inv_2 = Fq::from(2).invert().unwrap();

            // ─── 64-bit range proof per amount ──────────────────────
            for &amount in &all_amounts {
                let z_0 = Fq::from(amount);
                region.assign_advice(|| "z_0", config.advice[0], offset, || Value::known(z_0))?;
                region.assign_advice(|| "z_0_bit", config.advice[1], offset, || Value::known(Fq::zero()))?;

                let mut z_prev = z_0;
                let mut remaining = amount;
                for _bit_pos in 0..64 {
                    offset += 1;
                    config.s_running_sum.enable(&mut region, offset)?;

                    let bit_val = remaining & 1;
                    let bit_fq = Fq::from(bit_val);
                    let z_cur = (z_prev - bit_fq) * inv_2;

                    region.assign_advice(|| "z_cur", config.advice[0], offset, || Value::known(z_cur))?;
                    region.assign_advice(|| "bit", config.advice[1], offset, || Value::known(bit_fq))?;

                    z_prev = z_cur;
                    remaining >>= 1;
                }
                // Constrain z_64 = 0 (A-1 soundness fix: prover can't claim amount > 2^64−1)
                offset += 1;
                config.s_zero_check.enable(&mut region, offset)?;
                region.assign_advice(|| "z_64_zero", config.advice[0], offset, || Value::known(z_prev))?;
                region.assign_advice(|| "zero", config.advice[2], offset, || Value::known(Fq::ZERO))?;

                offset += 1; // gap / next z_0
            }

            // ─── Conservation running sum ───────────────────────────
            let n_in = self.amounts_in.len();
            offset += 1; // initial running_sum = 0 (no gate)
            region.assign_advice(|| "run_sum_0", config.advice[2], offset, || Value::known(Fq::ZERO))?;

            let mut running_sum = Fq::ZERO;
            for (i, &amount) in all_amounts.iter().enumerate() {
                offset += 1;
                let signed: Fq = if i < n_in {
                    Fq::from(amount)
                } else {
                    Fq::ZERO - Fq::from(amount)
                };
                running_sum = running_sum + signed;
                region.assign_advice(|| "run_sum", config.advice[2], offset, || Value::known(running_sum))?;
                region.assign_advice(|| "signed_amt", config.advice[4], offset, || Value::known(signed))?;
                config.s_conservation.enable(&mut region, offset)?;
            }

            // ─── Final: bind running_sum to instance[0] via s_conservation ──
            // The gate enforces: cur - prev - signed = 0 where
            //   prev = advice[2][Rotation(-1)] = last computed running_sum
            //   cur  = advice[2][Rotation(0)]  = public_amount (from instance)
            //   signed = 0 (at this row)
            // → public_amount = running_sum_last = sum_in - sum_out ✓
            offset += 1;
            region.assign_advice(|| "zero_signed", config.advice[4], offset, || Value::known(Fq::ZERO))?;
            region.assign_advice_from_instance(
                || "pub_amt", config.instance, 0, config.advice[2], offset,
            )?;
            config.s_conservation.enable(&mut region, offset)?;

            // ─── Commitment bindings: instance[1+j] → advice[3] ────
            for (j, cm_set) in self.output_commitments.iter().enumerate() {
                let idx = n_in + j;
                if idx < all_amounts.len() && !cm_set.is_empty() {
                    region.assign_advice_from_instance(
                        || "commitment", config.instance, 1 + j, config.advice[3], offset,
                    )?;
                }
                if idx < all_amounts.len() {
                    offset += 1;
                }
            }

            Ok(())
        })
    }
}

pub fn build_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return blake3::hash(b"empty_tx_list").into();
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for chunk in layer.chunks(2) {
            let mut h = blake3::Hasher::new();
            h.update(&chunk[0]);
            if chunk.len() > 1 {
                h.update(&chunk[1]);
            } else {
                h.update(&chunk[0]);
            }
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

pub struct Halo2PastaBackend;

impl ZkProverSystem for Halo2PastaBackend {
    type Params = ParamsIPA<EpAffine>;
    type ProvingKey = halo2_proofs::plonk::ProvingKey<EpAffine>;
    type VerifyingKey = halo2_proofs::plonk::VerifyingKey<EpAffine>;

    fn ensure_params() -> &'static Self::Params {
        ensure_params()
    }

    fn ensure_keys(
        amounts_in_len: usize,
        amounts_out_len: usize,
    ) -> (Self::VerifyingKey, Self::ProvingKey) {
        ensure_keys(amounts_in_len, amounts_out_len)
    }

    fn prove_conservation(
        amounts_in: &[u64],
        amounts_out: &[u64],
        in_blindings: &[[u8; 32]],
        out_blindings: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> Vec<u8> {
        let (params, (_vk, pk)) = (
            ensure_params(),
            ensure_keys(amounts_in.len(), amounts_out.len()),
        );

        let padded_in_blindings: Vec<[u8; 32]> = if in_blindings.is_empty() {
            vec![[0u8; 32]; amounts_in.len()]
        } else {
            in_blindings.to_vec()
        };
        let padded_out_blindings: Vec<[u8; 32]> = if out_blindings.is_empty() {
            vec![[0u8; 32]; amounts_out.len()]
        } else {
            out_blindings.to_vec()
        };
        let padded_commitments: Vec<Vec<[u8; 32]>> = if output_commitments.is_empty() {
            amounts_out.iter().map(|_| vec![]).collect()
        } else {
            output_commitments.iter().map(|&cm| vec![cm]).collect()
        };

        let circuit = ValueConservationCircuit {
            amounts_in: amounts_in.to_vec(),
            amounts_out: amounts_out.to_vec(),
            in_blindings: padded_in_blindings,
            out_blindings: padded_out_blindings,
            output_commitments: padded_commitments,
            public_amount,
        };

        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        let instance_fq = if public_amount >= 0 {
            Fq::from(public_amount as u64)
        } else {
            Fq::ZERO - Fq::from(public_amount.unsigned_abs())
        };
        let mut instance_col = vec![instance_fq];
        for cm in output_commitments {
            instance_col.push(
                Fq::from_repr(*cm).into_option()
                    .expect("prove_conservation: invalid commitment bytes — must be canonical Fq repr")
            );
        }
        let instances = vec![instance_col];
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances], OsRng, &mut transcript,
        ).expect("prove_conservation failed");
        let proof = transcript.finalize();
        let mut full = b"halo2_ipa_pasta_v1_".to_vec();
        full.extend_from_slice(&(amounts_in.len() as u16).to_le_bytes());
        full.extend_from_slice(&(amounts_out.len() as u16).to_le_bytes());
        full.extend_from_slice(&proof);
        full
    }

    fn verify_conservation(
        proof: &[u8],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> bool {
        const PREFIX: &[u8] = b"halo2_ipa_pasta_v1_";
        const PREFIX_LEN: usize = 19;
        const SHAPE_LEN: usize = 4;
        const MAX_PROOF_IOPS: usize = 30;
        if proof.len() < PREFIX_LEN + SHAPE_LEN || !proof.starts_with(PREFIX) {
            return false;
        }
        let in_len = u16::from_le_bytes(proof[PREFIX_LEN..PREFIX_LEN + 2].try_into().unwrap()) as usize;
        let out_len = u16::from_le_bytes(
            proof[PREFIX_LEN + 2..PREFIX_LEN + SHAPE_LEN].try_into().unwrap(),
        ) as usize;
        if in_len + out_len > MAX_PROOF_IOPS {
            return false;
        }
        let inner_proof = &proof[PREFIX_LEN + SHAPE_LEN..];

        let (params, (vk, _)) = (ensure_params(), ensure_keys(in_len, out_len));

        let instance_fq = if public_amount >= 0 {
            Fq::from(public_amount as u64)
        } else {
            Fq::ZERO - Fq::from(public_amount.unsigned_abs())
        };
        let mut instance_col = vec![instance_fq];
        for cm in output_commitments {
            match Fq::from_repr(*cm).into_option() {
                Some(fq) => instance_col.push(fq),
                None => return false,
            }
        }
        let instances = vec![instance_col];

        let mut transcript = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(inner_proof);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut transcript,
        ) {
            Ok(strategy) => strategy.finalize(),
            Err(_) => false,
        }
    }

    fn aggregate_proofs(
        last_agg: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[TxCommitments],
        tx_public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let proof_hashes: Vec<[u8; 32]> = tx_proofs.iter()
            .map(|p| blake3::hash(p).into())
            .collect();
        let merkle_root = build_merkle_root(&proof_hashes);

        let mut hasher = blake3::Hasher::new();
        hasher.update(blake3::hash(last_agg).as_bytes());
        hasher.update(&merkle_root);
        hasher.update(&height.to_le_bytes());
        hasher.update(state_root);
        let binding_hash = hasher.finalize();
        
        let mut agg = b"aetheris_aggregate_v1_".to_vec();
        agg.extend_from_slice(binding_hash.as_bytes());
        agg.extend_from_slice(&merkle_root);
        agg.extend_from_slice(&(tx_proofs.len() as u64).to_le_bytes());

        for (i, proof) in tx_proofs.iter().enumerate() {
            if proof.is_empty() { continue; }
            let commitments = tx_commitments.get(i).cloned().unwrap_or_default();
            let pub_amt = tx_public_amounts.get(i).copied().unwrap_or(0);
            if !Self::verify_conservation(proof, &commitments, pub_amt) {
                return Err(format!("Tx proof {} failed conservation verification", i));
            }
        }

        Ok(agg)
    }

    fn verify_aggregate(
        agg_proof: &[u8],
        prev_agg: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[TxCommitments],
        tx_public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> bool {
        if !agg_proof.starts_with(b"aetheris_aggregate_v1_") {
            return false;
        }
        let binding_hash = &agg_proof[22..54];
        let merkle_root = &agg_proof[54..86];

        let proof_hashes: Vec<[u8; 32]> = tx_proofs.iter()
            .map(|p| blake3::hash(p).into())
            .collect();
        let expected_merkle = build_merkle_root(&proof_hashes);
        if merkle_root != &expected_merkle[..] {
            return false;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(blake3::hash(prev_agg).as_bytes());
        hasher.update(&expected_merkle);
        hasher.update(&height.to_le_bytes());
        hasher.update(state_root);
        let expected_binding = hasher.finalize();
        if binding_hash != expected_binding.as_bytes() {
            return false;
        }

        for (i, proof) in tx_proofs.iter().enumerate() {
            if proof.is_empty() { continue; }
            let commitments = tx_commitments.get(i).cloned().unwrap_or_default();
            let pub_amt = tx_public_amounts.get(i).copied().unwrap_or(0);
            if !Self::verify_conservation(proof, &commitments, pub_amt) {
                return false;
            }
        }

        true
    }
}

impl Halo2PastaBackend {
    /// Prove membership of a leaf (note commitment) in the Merkle tree,
    /// and that the nullifier H(sk, index) matches the claimed value.
    /// Public instances: [merkle_root, nullifier].
    /// Wire format: 19-byte prefix + 4-byte depth (u32 LE) + inner Halo2 proof.
    pub fn prove_membership(
        leaf: &[u8; 32],
        path_siblings: &[[u8; 32]],
        position_bits: &[bool],
        sk: &[u8; 32],
        index: u64,
        merkle_root: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Vec<u8> {
        let depth = path_siblings.len();
        let (params, (_vk, pk)) = (ensure_params(), ensure_membership_keys_for_depth(depth));

        let circuit = MembershipCircuit {
            leaf: *leaf,
            path_siblings: path_siblings.to_vec(),
            position_bits: position_bits.to_vec(),
            sk: *sk,
            index,
            merkle_root: *merkle_root,
            nullifier: *nullifier,
        };

        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        let root_fq = Fq::from_repr(*merkle_root).into_option().expect("merkle_root is canonical Fq");
        let nf_fq = Fq::from_repr(*nullifier).into_option().expect("nullifier is canonical Fq");
        let instances = vec![vec![root_fq, nf_fq]];

        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances], OsRng, &mut transcript,
        )
        .expect("prove_membership failed");
        let proof = transcript.finalize();
        let mut full = b"halo2_ipa_member_v1_".to_vec();
        full.extend_from_slice(&(depth as u32).to_le_bytes());
        full.extend_from_slice(&proof);
        full
    }

    /// Verify a membership proof produced by `prove_membership`.
    /// Returns true iff the proof is valid for the given `merkle_root` and `nullifier`.
    pub fn verify_membership(proof: &[u8], merkle_root: &[u8; 32], nullifier: &[u8; 32]) -> bool {
        const PREFIX: &[u8] = b"halo2_ipa_member_v1_";
        const PREFIX_LEN: usize = 20;
        const DEPTH_LEN: usize = 4;
        const MAX_DEPTH: usize = 32;
        if proof.len() < PREFIX_LEN + DEPTH_LEN || !proof.starts_with(PREFIX) {
            return false;
        }
        let depth = u32::from_le_bytes(
            proof[PREFIX_LEN..PREFIX_LEN + DEPTH_LEN]
                .try_into()
                .unwrap(),
        ) as usize;
        if depth == 0 || depth > MAX_DEPTH {
            return false;
        }
        let inner_proof = &proof[PREFIX_LEN + DEPTH_LEN..];

        let (params, (vk, _)) = (ensure_params(), ensure_membership_keys_for_depth(depth));

        let root_fq = match Fq::from_repr(*merkle_root).into_option() {
            Some(fq) => fq,
            None => return false,
        };
        let nf_fq = match Fq::from_repr(*nullifier).into_option() {
            Some(fq) => fq,
            None => return false,
        };
        let instances = vec![vec![root_fq, nf_fq]];

        let mut transcript = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(inner_proof);
        let result = verify_proof_with_strategy::<
            CommitmentSchemeIPA<EpAffine>,
            _,
            Challenge255<EpAffine>,
            Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>,
            SingleStrategyIPA<'_, EpAffine>,
        >(params, &vk, SingleStrategyIPA::new(params), &[instances], &mut transcript);
        match result {
            Ok(strategy) => strategy.finalize(),
            Err(e) => {
                eprintln!("[ZK] verify_membership error: {:?}", e);
                false
            }
        }
    }

    pub fn setup_params() -> ParamsIPA<EpAffine> {
        ParamsIPA::<EpAffine>::setup(
            PROVING_K,
            &mut ChaCha20Rng::from_seed(*b"Aetheris IPA deterministic v0.00"),
            "value_conservation",
        )
    }

    /// A-3: Sender-side DH encryption using recipient's public key (pk_d).
    /// Generates ephemeral keypair, computes DH(esk, pk_d), derives AES key.
    /// Panics if pk_d is all-zero (identity element → shared secret is zero).
    pub fn encrypt_for_recipient(
        pk_d: &[u8; 32],
        amount: u64,
        blinding: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        assert!(!pk_d.iter().all(|&b| b == 0), "encrypt_for_recipient: pk_d cannot be all-zero");
        let esk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk = PublicKey::from(&esk);
        let shared = {
            let pk = PublicKey::from(*pk_d);
            esk.diffie_hellman(&pk)
        };
        let key = blake3::hash(shared.as_bytes());
        let aes_key = Key::<Aes256Gcm>::from_slice(&key.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut plaintext = Vec::with_capacity(8 + 32);
        plaintext.extend_from_slice(&amount.to_le_bytes());
        plaintext.extend_from_slice(blinding);
        let ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encryption failed");
        let mut output = nonce.to_vec();
        output.extend_from_slice(&ct);
        (*epk.as_bytes(), output)
    }

    pub fn encrypt_output(
        recipient_vk: &[u8; 32],
        amount: u64,
        blinding: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        Self::encrypt_note(recipient_vk, &epk_pub.to_bytes(), amount, blinding)
    }

    pub fn encrypt_note(
        recipient_vk: &[u8; 32],
        epk: &[u8; 32],
        amount: u64,
        blinding: &[u8; 32],
    ) -> ([u8; 32], Vec<u8>) {
        let shared = {
            let sk = StaticSecret::from(*recipient_vk);
            let pk = PublicKey::from(*epk);
            sk.diffie_hellman(&pk)
        };
        let key = blake3::hash(shared.as_bytes());
        let aes_key = Key::<Aes256Gcm>::from_slice(&key.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&amount.to_le_bytes());
        plaintext.extend_from_slice(blinding);
        let ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encryption failed");
        let mut output = nonce.to_vec();
        output.extend_from_slice(&ct);
        (epk.to_owned(), output)
    }

    pub fn trial_decrypt(
        viewing_key: &[u8; 32],
        epk: &[u8; 32],
        ciphertext: &[u8],
    ) -> Option<(u64, [u8; 32])> {
        if ciphertext.len() < 12 {
            return None;
        }
        let shared = {
            let sk = StaticSecret::from(*viewing_key);
            let pk = PublicKey::from(*epk);
            sk.diffie_hellman(&pk)
        };
        let key = blake3::hash(shared.as_bytes());
        let aes_key = Key::<Aes256Gcm>::from_slice(&key.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..];
        cipher.decrypt(nonce, ct).ok().and_then(|plaintext| {
            if plaintext.len() < 16 { return None; }
            let amount = u64::from_le_bytes(plaintext[..8].try_into().ok()?);
            let mut blinding = [0u8; 32];
            blinding.copy_from_slice(&plaintext[8..40]);
            Some((amount, blinding))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_merkle_leaf(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_le_bytes());
        b
    }

    fn make_proof(amounts_in: &[u64], amounts_out: &[u64], commitments: &[[u8; 32]], pub_amt: i64) -> Vec<u8> {
        Halo2PastaBackend::prove_conservation(amounts_in, amounts_out, &[], &[], commitments, pub_amt)
    }

    #[test]
    fn test_witness_bool_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{
                Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
            },
            poly::Rotation,
        };

        #[derive(Clone)]
        struct WBConfig {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct WBCircuit {
            leaf: Fq,
            bits: Vec<bool>,
        }

        impl Circuit<Fq> for WBCircuit {
            type Config = WBConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { self.clone() }

            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                meta.enable_equality(leaf);
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(leaf, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                WBConfig { poseidon, leaf, s_bool, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let leaf_cell = layouter.assign_region(|| "witness", |mut region| {
                    let lc = region.assign_advice(|| "leaf", config.leaf, 0, || Value::known(self.leaf))?;
                    for (i, &b) in self.bits.iter().enumerate() {
                        config.s_bool.enable(&mut region, 1 + i)?;
                        region.assign_advice(|| format!("bit_{}", i), config.leaf, 1 + i,
                            || Value::known(if b { Fq::one() } else { Fq::ZERO }))?;
                    }
                    Ok(lc.cell())
                })?;
                let one = Fq::one();
                let hash_cell = chip.assign_hash(layouter.namespace(|| "hash"), Value::known(self.leaf), Value::known(one), Some(leaf_cell), None)?;
                layouter.assign_region(|| "constrain", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "inst", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(hash_cell.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }

        let params = ensure_params();
        let dummy = WBCircuit { leaf: Fq::ZERO, bits: vec![false] };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");

        let leaf = Fq::from(42u64);
        let spec = ensure_poseidon_spec();
        let mut state = [leaf, Fq::one(), Fq::ZERO];
        poseidon_permute(spec, &mut state);
        let expected = state[0];
        let circuit = WBCircuit { leaf, bits: vec![true] };
        let instances = vec![vec![expected]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "witness_bool verify returned false"),
            Err(e) => panic!("witness_bool verify error: {:?}", e),
        }
        eprintln!("WITNESS_BOOL IPA ROUNDTRIP OK");
    }

    #[test]
    fn test_merkle2_nf_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector},
            poly::Rotation,
        };

        #[derive(Clone)]
        struct M2Config {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            sib0: Column<Advice>,
            sib1: Column<Advice>,
            sk: Column<Advice>,
            idx: Column<Advice>,
            bit: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct M2Circuit {
            leaf: Fq,
            sib0: Fq,
            sib1: Fq,
            sk: Fq,
            index: Fq,
        }

        impl Circuit<Fq> for M2Circuit {
            type Config = M2Config;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { self.clone() }

            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let sib0 = meta.advice_column();
                let sib1 = meta.advice_column();
                let sk = meta.advice_column();
                let idx = meta.advice_column();
                let bit = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                for c in [&leaf, &sib0, &sib1, &sk, &idx, &bit] {
                    meta.enable_equality(*c);
                }
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(bit, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                M2Config { poseidon, leaf, sib0, sib1, sk, idx, bit, s_bool, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let witnesses = layouter.assign_region(|| "witness", |mut region| {
                    let lc = region.assign_advice(|| "leaf", config.leaf, 0, || Value::known(self.leaf))?;
                    let s0c = region.assign_advice(|| "sib0", config.sib0, 1, || Value::known(self.sib0))?;
                    let s1c = region.assign_advice(|| "sib1", config.sib1, 2, || Value::known(self.sib1))?;
                    config.s_bool.enable(&mut region, 3)?;
                    region.assign_advice(|| "bit", config.bit, 3, || Value::known(Fq::one()))?;
                    let skc = region.assign_advice(|| "sk", config.sk, 4, || Value::known(self.sk))?;
                    let ic = region.assign_advice(|| "index", config.idx, 5, || Value::known(self.index))?;
                    Ok((lc.cell(), s0c.cell(), s1c.cell(), skc.cell(), ic.cell()))
                })?;
                let (leaf_cell, sib0_cell, sib1_cell, sk_cell, idx_cell) = witnesses;

                // H1 = H(leaf, sib0)
                let h1_native = chip.native_hash(self.leaf, self.sib0);
                let h1 = chip.assign_hash(layouter.namespace(|| "h1"), Value::known(self.leaf), Value::known(self.sib0), Some(leaf_cell), Some(sib0_cell))?;

                // H2 = H(h1_out, sib1) — BOTH cells copy-constrained
                let h2_native = chip.native_hash(h1_native, self.sib1);
                let h2 = chip.assign_hash(layouter.namespace(|| "h2"), Value::known(h1_native), Value::known(self.sib1), Some(h1.cell()), Some(sib1_cell))?;

                // Nullifier = H(sk, index)
                let nf_native = chip.native_hash(self.sk, self.index);
                let nf = chip.assign_hash(layouter.namespace(|| "nf"), Value::known(self.sk), Value::known(self.index), Some(sk_cell), Some(idx_cell))?;

                // instance[0] = h2, instance[1] = nf
                layouter.assign_region(|| "c0", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "r", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                layouter.assign_region(|| "c1", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "n", config.instance, 1, config.poseidon.state[0], 0)?;
                    region.constrain_equal(nf.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }

        let params = ensure_params();
        let dummy = M2Circuit { leaf: Fq::ZERO, sib0: Fq::ZERO, sib1: Fq::ZERO, sk: Fq::ZERO, index: Fq::ZERO };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");

        let leaf = Fq::from(3u64);
        let sib0 = Fq::from(5u64);
        let sib1 = Fq::from(7u64);
        let sk = Fq::from(9u64);
        let index = Fq::from(11u64);
        let spec = ensure_poseidon_spec();
        let mut s = [leaf, sib0, Fq::ZERO]; poseidon_permute(spec, &mut s);
        let mut s2 = [s[0], sib1, Fq::ZERO]; poseidon_permute(spec, &mut s2);
        let mut nf_s = [sk, index, Fq::ZERO]; poseidon_permute(spec, &mut nf_s);
        let circuit = M2Circuit { leaf, sib0, sib1, sk, index };
        let instances = vec![vec![s2[0], nf_s[0]]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "m2 verify returned false"),
            Err(e) => panic!("m2 verify error: {:?}", e),
        }
        eprintln!("M2 IPA ROUNDTRIP OK");
    }

    /// Same as M2 but uses a SINGLE `siblings` column (like MembershipCircuit).
    #[test]
    fn test_single_sib_col_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector},
            poly::Rotation,
        };

        #[derive(Clone)]
        struct SSConfig {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            siblings: Column<Advice>,   // single column for ALL siblings
            sk: Column<Advice>,
            idx: Column<Advice>,
            bit: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct SSCircuit {
            leaf: Fq,
            sib0: Fq,
            sib1: Fq,
            sk: Fq,
            index: Fq,
        }

        impl Circuit<Fq> for SSCircuit {
            type Config = SSConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { self.clone() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let siblings = meta.advice_column();
                let sk = meta.advice_column();
                let idx = meta.advice_column();
                let bit = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                for c in [&leaf, &siblings, &sk, &idx, &bit] {
                    meta.enable_equality(*c);
                }
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(bit, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                SSConfig { poseidon, leaf, siblings, sk, idx, bit, s_bool, instance }
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let witnesses = layouter.assign_region(|| "witness", |mut region| {
                    let lc = region.assign_advice(|| "leaf", config.leaf, 0, || Value::known(self.leaf))?;
                    let s0c = region.assign_advice(|| "sib0", config.siblings, 1, || Value::known(self.sib0))?;
                    let s1c = region.assign_advice(|| "sib1", config.siblings, 2, || Value::known(self.sib1))?;
                    config.s_bool.enable(&mut region, 3)?;
                    region.assign_advice(|| "bit", config.bit, 3, || Value::known(Fq::one()))?;
                    let skc = region.assign_advice(|| "sk", config.sk, 4, || Value::known(self.sk))?;
                    let ic = region.assign_advice(|| "index", config.idx, 5, || Value::known(self.index))?;
                    Ok((lc.cell(), s0c.cell(), s1c.cell(), skc.cell(), ic.cell()))
                })?;
                let (leaf_cell, sib0_cell, sib1_cell, sk_cell, idx_cell) = witnesses;
                let h1_native = chip.native_hash(self.leaf, self.sib0);
                let h1 = chip.assign_hash(layouter.namespace(|| "h1"), Value::known(self.leaf), Value::known(self.sib0), Some(leaf_cell), Some(sib0_cell))?;
                let h2_native = chip.native_hash(h1_native, self.sib1);
                let h2 = chip.assign_hash(layouter.namespace(|| "h2"), Value::known(h1_native), Value::known(self.sib1), Some(h1.cell()), Some(sib1_cell))?;
                let nf_native = chip.native_hash(self.sk, self.index);
                let nf = chip.assign_hash(layouter.namespace(|| "nf"), Value::known(self.sk), Value::known(self.index), Some(sk_cell), Some(idx_cell))?;
                layouter.assign_region(|| "c0", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "r", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                layouter.assign_region(|| "c1", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "n", config.instance, 1, config.poseidon.state[0], 0)?;
                    region.constrain_equal(nf.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }
        let params = ensure_params();
        let dummy = SSCircuit { leaf: Fq::ZERO, sib0: Fq::ZERO, sib1: Fq::ZERO, sk: Fq::ZERO, index: Fq::ZERO };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");
        let leaf = Fq::from(3u64);
        let sib0 = Fq::from(5u64);
        let sib1 = Fq::from(7u64);
        let sk = Fq::from(9u64);
        let index = Fq::from(11u64);
        let spec = ensure_poseidon_spec();
        let mut s = [leaf, sib0, Fq::ZERO]; poseidon_permute(spec, &mut s);
        let mut s2 = [s[0], sib1, Fq::ZERO]; poseidon_permute(spec, &mut s2);
        let mut nf_s = [sk, index, Fq::ZERO]; poseidon_permute(spec, &mut nf_s);
        let circuit = SSCircuit { leaf, sib0, sib1, sk, index };
        let instances = vec![vec![s2[0], nf_s[0]]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "ss verify returned false"),
            Err(e) => panic!("ss verify error: {:?}", e),
        }
        eprintln!("SINGLE SIB COL IPA ROUNDTRIP OK");
    }

    /// Tests swapped order: H2 first_cell = sib (siblings col), second_cell = h1_out (state col)
    #[test]
    fn test_swapped_order_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector},
            poly::Rotation,
        };

        #[derive(Clone)]
        struct SwapConfig {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            sib0: Column<Advice>,
            sib1: Column<Advice>,
            sk: Column<Advice>,
            idx: Column<Advice>,
            bit: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct SwapCircuit {
            leaf: Fq,
            sib0: Fq,
            sib1: Fq,
            sk: Fq,
            index: Fq,
        }

        impl Circuit<Fq> for SwapCircuit {
            type Config = SwapConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { self.clone() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let sib0 = meta.advice_column();
                let sib1 = meta.advice_column();
                let sk = meta.advice_column();
                let idx = meta.advice_column();
                let bit = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                for c in [&leaf, &sib0, &sib1, &sk, &idx, &bit] { meta.enable_equality(*c); }
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(bit, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                SwapConfig { poseidon, leaf, sib0, sib1, sk, idx, bit, s_bool, instance }
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let witnesses = layouter.assign_region(|| "witness", |mut region| {
                    let lc = region.assign_advice(|| "leaf", config.leaf, 0, || Value::known(self.leaf))?;
                    let s0c = region.assign_advice(|| "sib0", config.sib0, 1, || Value::known(self.sib0))?;
                    let s1c = region.assign_advice(|| "sib1", config.sib1, 2, || Value::known(self.sib1))?;
                    config.s_bool.enable(&mut region, 3)?;
                    region.assign_advice(|| "bit", config.bit, 3, || Value::known(Fq::one()))?;
                    let skc = region.assign_advice(|| "sk", config.sk, 4, || Value::known(self.sk))?;
                    let ic = region.assign_advice(|| "index", config.idx, 5, || Value::known(self.index))?;
                    Ok((lc.cell(), s0c.cell(), s1c.cell(), skc.cell(), ic.cell()))
                })?;
                let (leaf_cell, sib0_cell, sib1_cell, sk_cell, idx_cell) = witnesses;

                // H1 = H(leaf, sib0) — normal order
                let h1_native = chip.native_hash(self.leaf, self.sib0);
                let h1 = chip.assign_hash(layouter.namespace(|| "h1"), Value::known(self.leaf), Value::known(self.sib0), Some(leaf_cell), Some(sib0_cell))?;

                // H2 = H(h1_out, sib1) — SWAPPED: sib1 goes FIRST, prev hash output goes SECOND
                // This mimics position_bits=true in the membership circuit
                let h2_native = chip.native_hash(self.sib1, h1_native); // swapped native
                // first_cell = Some(sib1_cell), second_cell = Some(h1.cell())
                let h2 = chip.assign_hash(layouter.namespace(|| "h2"), Value::known(self.sib1), Value::known(h1_native), Some(sib1_cell), Some(h1.cell()))?;

                // Nullifier
                let nf_native = chip.native_hash(self.sk, self.index);
                let nf = chip.assign_hash(layouter.namespace(|| "nf"), Value::known(self.sk), Value::known(self.index), Some(sk_cell), Some(idx_cell))?;

                layouter.assign_region(|| "c0", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "r", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                layouter.assign_region(|| "c1", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "n", config.instance, 1, config.poseidon.state[0], 0)?;
                    region.constrain_equal(nf.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }
        let params = ensure_params();
        let dummy = SwapCircuit { leaf: Fq::ZERO, sib0: Fq::ZERO, sib1: Fq::ZERO, sk: Fq::ZERO, index: Fq::ZERO };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");
        let leaf = Fq::from(3u64);
        let sib0 = Fq::from(5u64);
        let sib1 = Fq::from(7u64);
        let sk = Fq::from(9u64);
        let index = Fq::from(11u64);
        let spec = ensure_poseidon_spec();
        let mut s = [leaf, sib0, Fq::ZERO]; poseidon_permute(spec, &mut s);
        let mut s2 = [sib1, s[0], Fq::ZERO]; poseidon_permute(spec, &mut s2); // swapped order
        let mut nf_s = [sk, index, Fq::ZERO]; poseidon_permute(spec, &mut nf_s);
        let circuit = SwapCircuit { leaf, sib0, sib1, sk, index };
        let instances = vec![vec![s2[0], nf_s[0]]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "swap verify returned false"),
            Err(e) => panic!("swap verify error: {:?}", e),
        }
        eprintln!("SWAP IPA ROUNDTRIP OK");
    }

    /// Single siblings column + swapped order (like MembershipCircuit when position_bits has mixed entries)
    #[test]
    fn test_ss_swap_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector},
            poly::Rotation,
        };

        #[derive(Clone)]
        struct SSSConfig {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            siblings: Column<Advice>,
            sk: Column<Advice>,
            idx: Column<Advice>,
            bit: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct SSSCircuit {
            leaf: Fq,
            sib0: Fq,
            sib1: Fq,
            sk: Fq,
            index: Fq,
        }

        impl Circuit<Fq> for SSSCircuit {
            type Config = SSSConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { self.clone() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let siblings = meta.advice_column();
                let sk = meta.advice_column();
                let idx = meta.advice_column();
                let bit = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                for c in [&leaf, &siblings, &sk, &idx, &bit] { meta.enable_equality(*c); }
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(bit, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                SSSConfig { poseidon, leaf, siblings, sk, idx, bit, s_bool, instance }
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let witnesses = layouter.assign_region(|| "witness", |mut region| {
                    let lc = region.assign_advice(|| "leaf", config.leaf, 0, || Value::known(self.leaf))?;
                    let s0c = region.assign_advice(|| "sib0", config.siblings, 1, || Value::known(self.sib0))?;
                    let s1c = region.assign_advice(|| "sib1", config.siblings, 2, || Value::known(self.sib1))?;
                    config.s_bool.enable(&mut region, 3)?;
                    region.assign_advice(|| "bit", config.bit, 3, || Value::known(Fq::one()))?;
                    let skc = region.assign_advice(|| "sk", config.sk, 4, || Value::known(self.sk))?;
                    let ic = region.assign_advice(|| "index", config.idx, 5, || Value::known(self.index))?;
                    Ok((lc.cell(), s0c.cell(), s1c.cell(), skc.cell(), ic.cell()))
                })?;
                let (leaf_cell, sib0_cell, sib1_cell, sk_cell, idx_cell) = witnesses;

                // H1: normal order
                let h1_native = chip.native_hash(self.leaf, self.sib0);
                let h1 = chip.assign_hash(layouter.namespace(|| "h1"), Value::known(self.leaf), Value::known(self.sib0), Some(leaf_cell), Some(sib0_cell))?;

                // H2: swapped — sib1→state[0], h1_out→state[1] (mimics position_bits true)
                let h2_native = chip.native_hash(self.sib1, h1_native);
                let h2 = chip.assign_hash(layouter.namespace(|| "h2"), Value::known(self.sib1), Value::known(h1_native), Some(sib1_cell), Some(h1.cell()))?;

                let nf_native = chip.native_hash(self.sk, self.index);
                let nf = chip.assign_hash(layouter.namespace(|| "nf"), Value::known(self.sk), Value::known(self.index), Some(sk_cell), Some(idx_cell))?;

                layouter.assign_region(|| "c0", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "r", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                layouter.assign_region(|| "c1", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "n", config.instance, 1, config.poseidon.state[0], 0)?;
                    region.constrain_equal(nf.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }
        let params = ensure_params();
        let dummy = SSSCircuit { leaf: Fq::ZERO, sib0: Fq::ZERO, sib1: Fq::ZERO, sk: Fq::ZERO, index: Fq::ZERO };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");
        let leaf = Fq::from(3u64);
        let sib0 = Fq::from(5u64);
        let sib1 = Fq::from(7u64);
        let sk = Fq::from(9u64);
        let index = Fq::from(11u64);
        let spec = ensure_poseidon_spec();
        let mut s = [leaf, sib0, Fq::ZERO]; poseidon_permute(spec, &mut s);
        let mut s2 = [sib1, s[0], Fq::ZERO]; poseidon_permute(spec, &mut s2);
        let mut nf_s = [sk, index, Fq::ZERO]; poseidon_permute(spec, &mut nf_s);
        let circuit = SSSCircuit { leaf, sib0, sib1, sk, index };
        let instances = vec![vec![s2[0], nf_s[0]]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "sss verify returned false"),
            Err(e) => panic!("sss verify error: {:?}", e),
        }
        eprintln!("SS SWAP IPA ROUNDTRIP OK");
    }

    /// Imports MembershipCircuit directly and runs IPA roundtrip
    #[test]
    fn test_membership_direct_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::membership_circuit::{MembershipCircuit, MEMBERSHIP_K};
        use crate::merkle_tree::IncrementalMerkleTree;
        use crate::poseidon_fq;

        let mut tree = IncrementalMerkleTree::new();
        for i in 0..4u64 {
            let mut leaf_bytes = [0u8; 32];
            leaf_bytes[..8].copy_from_slice(&i.to_le_bytes());
            tree.append(leaf_bytes);
        }
        let sk = Fq::from(42u64).to_repr();
        let index = 2u64;
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[..8].copy_from_slice(&index.to_le_bytes());
        let mut index_bytes = [0u8; 32];
        index_bytes[..8].copy_from_slice(&index.to_le_bytes());
        let nf = poseidon_fq::poseidon_hash(&sk, &index_bytes);

        let path = tree.path(index as usize).unwrap();

        let params = ensure_params();
        let circuit = MembershipCircuit {
            leaf: leaf_bytes,
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index,
            merkle_root: *tree.root(),
            nullifier: nf,
        };
        let (vk, pk) = ensure_membership_keys(&circuit);

        let root_fq = Fq::from_repr(*tree.root()).into_option().unwrap();
        let nf_fq = Fq::from_repr(nf).into_option().unwrap();
        let instances = vec![vec![root_fq, nf_fq]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("membership direct create_proof failed");
        let proof = transcript.finalize();
        eprintln!("DIRECT membership proof len={}", proof.len());
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "direct membership verify false"),
            Err(e) => panic!("direct membership verify error: {:?}", e),
        }
        eprintln!("MEMBERSHIP DIRECT IPA OK");
    }

    /// Exact membership structure: 5 witness cols, 2 bit rows (gap after sibs),
    /// sk+index with gap before, BOTH inputs copy-constrained, swapped second hash.
    #[test]
    fn test_exact_membership_structure_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::{ensure_poseidon_spec, poseidon_permute};
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
            plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector},
            poly::Rotation,
        };

        #[derive(Clone)]
        struct ExactConfig {
            poseidon: PoseidonFqConfig,
            leaf: Column<Advice>,
            siblings: Column<Advice>,
            sk: Column<Advice>,
            idx: Column<Advice>,
            bit: Column<Advice>,
            s_bool: Selector,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct ExactCircuit {
            leaf: Fq,
            sibs: Vec<Fq>,
            pos_bits: Vec<bool>,
            sk: Fq,
            index: Fq,
        }

        impl Circuit<Fq> for ExactCircuit {
            type Config = ExactConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self { leaf: Fq::ZERO, sibs: vec![Fq::ZERO; self.sibs.len()], pos_bits: self.pos_bits.clone(), sk: Fq::ZERO, index: Fq::ZERO }
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let leaf = meta.advice_column();
                let siblings = meta.advice_column();
                let sk = meta.advice_column();
                let idx = meta.advice_column();
                let bit = meta.advice_column();
                let s_bool = meta.selector();
                let instance = meta.instance_column();
                for c in [&leaf, &siblings, &sk, &idx, &bit] { meta.enable_equality(*c); }
                meta.enable_equality(instance);
                meta.create_gate("bool_check", |meta| {
                    let s = meta.query_selector(s_bool);
                    let b = meta.query_advice(bit, Rotation::cur());
                    vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
                });
                ExactConfig { poseidon, leaf, siblings, sk, idx, bit, s_bool, instance }
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let depth = self.sibs.len();
                let chip = PoseidonFqChip::new(config.poseidon.clone());

                // Same as MembersipCircuit but SINGLE bit row + sk at 4, index at 5
                let witness = layouter.assign_region(|| "witnesses", |mut region| {
                    let mut offset = 0usize;
                    let lc = region.assign_advice(|| "leaf", config.leaf, offset, || Value::known(self.leaf))?;
                    let mut sc = Vec::new();
                    for i in 0..depth {
                        offset += 1;
                        let c = region.assign_advice(|| format!("sib_{}", i), config.siblings, offset, || Value::known(self.sibs[i]))?;
                        sc.push(c);
                    }
                    // Single bit row (like SS Swap and all passing tests)
                    offset += 1;
                    config.s_bool.enable(&mut region, offset)?;
                    region.assign_advice(|| "bit", config.bit, offset, || Value::known(Fq::one()))?;
                    offset += 1;
                    let skc = region.assign_advice(|| "sk", config.sk, offset, || Value::known(self.sk))?;
                    offset += 1;
                    let ic = region.assign_advice(|| "index", config.idx, offset, || Value::known(self.index))?;
                    Ok((lc.cell(), sc.iter().map(|a| a.cell()).collect::<Vec<_>>(), skc.cell(), ic.cell()))
                })?;
                let (leaf_cell, sibling_cells, sk_cell, index_cell) = witness;

                // Loop with pos_bits branching
                let mut current_val = self.leaf;
                let mut current_cell = leaf_cell;
                for i in 0..self.sibs.len() {
                    if !self.pos_bits[i] {
                        let hc = chip.assign_hash(layouter.namespace(|| format!("h{}", i)), Value::known(current_val), Value::known(self.sibs[i]), Some(current_cell), Some(sibling_cells[i]))?;
                        current_val = chip.native_hash(current_val, self.sibs[i]);
                        current_cell = hc.cell();
                    } else {
                        let hc = chip.assign_hash(layouter.namespace(|| format!("h{}", i)), Value::known(self.sibs[i]), Value::known(current_val), Some(sibling_cells[i]), Some(current_cell))?;
                        current_val = chip.native_hash(self.sibs[i], current_val);
                        current_cell = hc.cell();
                    }
                }
                let current_cell = current_cell;

                // Nullifier hash (BEFORE root constraint, like SS Swap)
                let nf_cell = chip.assign_hash(layouter.namespace(|| "nullifier"), Value::known(self.sk), Value::known(self.index), Some(sk_cell), Some(index_cell))?;

                // Constrain root to instance[0] (AFTER nullifier, matching SS Swap)
                layouter.assign_region(|| "constrain_root", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "root", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(current_cell, ic.cell())?;
                    Ok(())
                })?;

                // Constrain nullifier to instance[1]
                // Use row 1 like MembershipCircuit (also put before root)
                layouter.assign_region(|| "constrain_nullifier", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "nf", config.instance, 1, config.poseidon.state[0], 1)?;
                    region.constrain_equal(nf_cell.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }

        let params = ensure_params();
        let leaf = Fq::from(3u64);
        let sibs = vec![Fq::from(5u64), Fq::from(7u64)];
        let pos_bits = vec![false, true]; // match SS Swap: second hash swapped
        let sk = Fq::from(9u64);
        let index = Fq::from(11u64);
        let spec = ensure_poseidon_spec();
        let mut cur = leaf;
        for i in 0..2 {
            let mut s = if !pos_bits[i] { [cur, sibs[i], Fq::ZERO] } else { [sibs[i], cur, Fq::ZERO] };
            poseidon_permute(spec, &mut s);
            cur = s[0];
        }
        let mut nf_s = [sk, index, Fq::ZERO]; poseidon_permute(spec, &mut nf_s);
        let circuit = ExactCircuit { leaf, sibs, pos_bits, sk, index };
        // NOTE: keygen takes the real circuit; without_witnesses() zeros witnesses but preserves pos_bits
        let vk = keygen_vk(params, &circuit).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &circuit).expect("keygen_pk");
        let instances = vec![vec![cur, nf_s[0]]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r,
        ) {
            Ok(strategy) => assert!(strategy.finalize(), "exact verify returned false"),
            Err(e) => panic!("exact verify error: {:?}", e),
        }
        eprintln!("EXACT IPA ROUNDTRIP OK");
    }

    #[test]
    fn test_chained_poseidon_mock() {
        use crate::poseidon_fq::poseidon_hash;
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            dev::MockProver,
            plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
        };

        #[derive(Clone)]
        struct ChainedConfig {
            poseidon: PoseidonFqConfig,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct ChainedCircuit {
            a: [u8; 32],
            b: [u8; 32],
        }

        impl Circuit<Fq> for ChainedCircuit {
            type Config = ChainedConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { self.clone() }

            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                ChainedConfig { poseidon, instance }
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let a_fq = Fq::from_repr(self.a).into_option().unwrap();
                let b_fq = Fq::from_repr(self.b).into_option().unwrap();
                let h1_native = chip.native_hash(a_fq, b_fq);
                let h1 = chip.assign_hash(layouter.namespace(|| "hash1"), Value::known(a_fq), Value::known(b_fq), None, None)?;
                let h2 = chip.assign_hash(layouter.namespace(|| "hash2"), Value::known(h1_native), Value::known(a_fq), Some(h1.cell()), None)?;
                layouter.assign_region(|| "constrain", |mut region| {
                    let ic = region.assign_advice_from_instance(|| "inst", config.instance, 0, config.poseidon.state[0], 0)?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }

        let a = [0u8; 32];
        let b = [0u8; 32];
        let h1_repr = poseidon_hash(&a, &b);
        let h2_repr = poseidon_hash(&h1_repr, &a);
        let expected = Fq::from_repr(h2_repr).into_option().unwrap();
        let circuit = ChainedCircuit { a, b };
        let prover = MockProver::run(11, &circuit, vec![vec![expected]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        eprintln!("CHAINED MOCKPROVER OK");
    }

    #[test]
    fn test_chained_poseidon_ipa() {
        unsafe { std::env::set_var("AETHERIS_DBG", "1"); }

        use crate::poseidon_fq::poseidon_hash;
        use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner, Value},
            plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
        };

        #[derive(Clone)]
        struct ChainedConfig {
            poseidon: PoseidonFqConfig,
            instance: Column<Instance>,
        }

        #[derive(Clone)]
        struct ChainedCircuit {
            a: [u8; 32],
            b: [u8; 32],
        }

        impl Circuit<Fq> for ChainedCircuit {
            type Config = ChainedConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                self.clone()
            }

            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let poseidon = PoseidonFqChip::configure(meta);
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                ChainedConfig { poseidon, instance }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let chip = PoseidonFqChip::new(config.poseidon.clone());
                let a_fq = Fq::from_repr(self.a).into_option().unwrap();
                let b_fq = Fq::from_repr(self.b).into_option().unwrap();

                // Chain TWO hashes: hash1 = H(a, b), hash2 = H(hash1_out, a)
                // The second hash's first input is the output of hash1.
                let h1_native = chip.native_hash(a_fq, b_fq);
                let h1 = chip.assign_hash(
                    layouter.namespace(|| "hash1"),
                    Value::known(a_fq), Value::known(b_fq),
                    None, None,
                )?;
                let h2 = chip.assign_hash(
                    layouter.namespace(|| "hash2"),
                    Value::known(h1_native), Value::known(a_fq),
                    Some(h1.cell()), None,
                )?;

                layouter.assign_region(|| "constrain", |mut region| {
                    let ic = region.assign_advice_from_instance(
                        || "inst", config.instance, 0, config.poseidon.state[0], 0,
                    )?;
                    region.constrain_equal(h2.cell(), ic.cell())?;
                    Ok(())
                })?;
                Ok(())
            }
        }

        let params = ensure_params();
        let dummy = ChainedCircuit { a: [0u8; 32], b: [0u8; 32] };
        let vk = keygen_vk(params, &dummy).expect("keygen_vk");
        let pk = keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk");

        let a_bytes = { let mut b = [0u8; 32]; b[0] = 42; b };
        let b_bytes = { let mut b = [0u8; 32]; b[0] = 7; b };
        let h1_repr = poseidon_hash(&a_bytes, &b_bytes);
        let h2_repr = poseidon_hash(&h1_repr, &a_bytes);
        let expected = Fq::from_repr(h2_repr).into_option().unwrap();
        let circuit = ChainedCircuit { a: a_bytes, b: b_bytes };
        let instances = vec![vec![expected]];
        let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);
        create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
            params, &pk, &[circuit], &[instances.clone()], OsRng, &mut transcript,
        ).expect("create_proof");
        let proof = transcript.finalize();
        eprintln!("chained proof len={}", proof.len());

        let mut r = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(&proof[..]);
        match verify_proof_with_strategy::<
            CommitmentSchemeIPA<EpAffine>, _,
            Challenge255<EpAffine>,
            Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>,
            SingleStrategyIPA<'_, EpAffine>,
        >(params, &vk, SingleStrategyIPA::new(params), &[instances], &mut r) {
            Ok(strategy) => assert!(strategy.finalize(), "chained verify returned false"),
            Err(e) => panic!("chained verify error: {:?}", e),
        }
        eprintln!("CHAINED IPA ROUNDTRIP OK");
    }

    #[test]
    fn test_membership_public_api_roundtrip() {
        use crate::merkle_tree::IncrementalMerkleTree;
        use crate::poseidon_fq;

        let mut tree = IncrementalMerkleTree::new();
        for i in 0..4u64 {
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&i.to_le_bytes());
            tree.append(leaf);
        }
        let index = 2u64;
        let mut leaf = [0u8; 32];
        leaf[..8].copy_from_slice(&index.to_le_bytes());
        let sk = Fq::from(42u64).to_repr();
        let nf = poseidon_fq::poseidon_nullifier(&sk, index);

        let path = tree.path(index as usize).unwrap();
        let root = *tree.root();

        let proof = Halo2PastaBackend::prove_membership(
            &leaf, &path.siblings, &path.position_bits, &sk, index, &root, &nf,
        );
        assert!(Halo2PastaBackend::verify_membership(&proof, &root, &nf),
            "public API membership roundtrip should verify");
        let fake_root = [0xFFu8; 32];
        assert!(!Halo2PastaBackend::verify_membership(&proof, &fake_root, &nf),
            "wrong root should be rejected");
    }

    #[test]
    fn test_conservation_basic() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[100], &[100], &commitments, 0);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, 0));
    }

    #[test]
    fn test_conservation_rejects_wrong_public_amount() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[100], &[100], &commitments, 0);
        assert!(!Halo2PastaBackend::verify_conservation(&proof, &commitments, 1));
    }

    #[test]
    fn test_conservation_public_amount_net_zero() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[100], &[80], &commitments, 20);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, 20));
    }

    #[test]
    fn test_conservation_negative_public_amount() {
        let commitments = vec![[0u8; 32]; 2];
        let proof = make_proof(&[50], &[70], &commitments, -20);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, -20));
    }

    /// Regression: (0 in, X out, public = -X) coinbase/mint shape used by FFI genesis/reward.
    /// Before sign fix, this shape panic'd at synthesis (net_value = -2*X != 0).
    #[test]
    fn test_mint_shape_proof_verifies() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[], &[1000], &commitments, -1000);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, -1000));
    }

    /// Multi-output mint: 2 outs, sum equals -public_amount.
    #[test]
    fn test_mint_shape_multi_out_proof_verifies() {
        let commitments = vec![[0u8; 32]; 2];
        let proof = make_proof(&[], &[500, 500], &commitments, -1000);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, -1000));
    }

    /// Regression: prove with WRONG sign (+amount) for a mint must be rejected by verifier
    /// (running_sum = -1000, instance[0] = 1000, so 1000 - (-1000) ≠ 0).
    #[test]
    fn test_mint_shape_wrong_sign_rejected_by_verifier() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[], &[1000], &commitments, 1000);
        assert!(!Halo2PastaBackend::verify_conservation(&proof, &commitments, 1000));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let vk = [0xABu8; 32];
        let blinding = [0x42u8; 32];
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        let (_epk_sent, ciphertext) = Halo2PastaBackend::encrypt_note(&vk, &epk_pub.to_bytes(), 12345, &blinding);
        let decrypted = Halo2PastaBackend::trial_decrypt(&vk, &epk_pub.to_bytes(), &ciphertext);
        assert_eq!(decrypted, Some((12345, blinding)));
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key() {
        let vk1 = [0xABu8; 32];
        let vk2 = [0xCDu8; 32];
        let blinding = [0x42u8; 32];
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        let (_epk_sent, ciphertext) = Halo2PastaBackend::encrypt_note(&vk1, &epk_pub.to_bytes(), 42, &blinding);
        let decrypted = Halo2PastaBackend::trial_decrypt(&vk2, &epk_pub.to_bytes(), &ciphertext);
        assert_eq!(decrypted, None);
    }

    #[test]
    fn test_encrypt_decrypt_tampered() {
        let vk = [0xABu8; 32];
        let blinding = [0x42u8; 32];
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        let (_epk_sent, mut ciphertext) = Halo2PastaBackend::encrypt_note(&vk, &epk_pub.to_bytes(), 999, &blinding);
        if ciphertext.len() > 12 {
            ciphertext[12] ^= 0xFF;
        }
        let decrypted = Halo2PastaBackend::trial_decrypt(&vk, &epk_pub.to_bytes(), &ciphertext);
        assert_eq!(decrypted, None);
    }

    #[test]
    fn test_large_value_roundtrip() {
        let amount = u64::MAX;
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[amount], &[amount], &commitments, 0);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, 0));
    }

    #[test]
    fn test_encrypt_decrypt_large_amount() {
        let vk = [0xABu8; 32];
        let blinding = [0x42u8; 32];
        let amount = 1234567890123u64;
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        let (_epk_sent, ciphertext) = Halo2PastaBackend::encrypt_note(&vk, &epk_pub.to_bytes(), amount, &blinding);
        let decrypted = Halo2PastaBackend::trial_decrypt(&vk, &epk_pub.to_bytes(), &ciphertext);
        assert_eq!(decrypted, Some((amount, blinding)));
    }

    #[test]
    fn test_encrypt_for_recipient_roundtrip() {
        let vk = [0xABu8; 32];
        let blinding = [0x42u8; 32];
        let amount = 12345u64;

        // Sender encrypts for pk_d
        let pk_d = {
            let sk = x25519_dalek::StaticSecret::from(vk);
            let pk = x25519_dalek::PublicKey::from(&sk);
            *pk.as_bytes()
        };

        let (epk, ciphertext) = Halo2PastaBackend::encrypt_for_recipient(&pk_d, amount, &blinding);

        // Recipient decrypts with viewing_key + epk
        let decrypted = Halo2PastaBackend::trial_decrypt(&vk, &epk, &ciphertext);
        assert_eq!(decrypted, Some((amount, blinding)));
    }

    #[test]
    fn test_encrypt_for_recipient_rejects_zero_pk_d() {
        let pk_d = [0u8; 32];
        let result = std::panic::catch_unwind(|| {
            Halo2PastaBackend::encrypt_for_recipient(&pk_d, 100, &[1u8; 32]);
        });
        assert!(result.is_err(), "encrypt_for_recipient should panic on all-zero pk_d");
    }

    #[test]
    fn test_encrypt_nonce_uniqueness() {
        let vk = [0xABu8; 32];
        let blinding = [0x42u8; 32];
        let epk = EphemeralSecret::random_from_rng(&mut OsRng);
        let epk_pub = PublicKey::from(&epk);
        let (_, ct1) = Halo2PastaBackend::encrypt_note(&vk, &epk_pub.to_bytes(), 42, &blinding);
        let (_, ct2) = Halo2PastaBackend::encrypt_note(&vk, &epk_pub.to_bytes(), 42, &blinding);
        assert_ne!(ct1, ct2, "Two encryptions should produce different ciphertexts");
    }

    #[test]
    fn test_aggregate_multi_tx_roundtrip() {
        let commitments1 = vec![[0u8; 32]; 1];
        let p1 = make_proof(&[10], &[10], &commitments1, 0);
        let commitments2 = vec![[0u8; 32]; 1];
        let p2 = make_proof(&[20], &[20], &commitments2, 0);

        let prev = b"aetheris_aggregate_v1_genesis_test";
        let agg = Halo2PastaBackend::aggregate_proofs(
            prev,
            &[p1.clone(), p2.clone()],
            &[commitments1.clone(), commitments2.clone()],
            &[0, 0],
            1,
            &[0u8; 32],
        ).unwrap();
        assert!(Halo2PastaBackend::verify_aggregate(
            &agg,
            prev,
            &[p1, p2],
            &[commitments1, commitments2],
            &[0, 0],
            1,
            &[0u8; 32],
        ));
    }

    #[test]
    fn test_aggregate_rejects_tampered() {
        let commitments1 = vec![[0u8; 32]; 1];
        let p1 = make_proof(&[10], &[10], &commitments1, 0);
        let commitments2 = vec![[0u8; 32]; 1];
        let p2 = make_proof(&[20], &[20], &commitments2, 0);

        let prev = b"aetheris_aggregate_v1_genesis_test";
        let agg = Halo2PastaBackend::aggregate_proofs(
            prev,
            &[p1.clone(), p2.clone()],
            &[commitments1.clone(), commitments2.clone()],
            &[0, 0],
            1,
            &[0u8; 32],
        ).unwrap();
        assert!(!Halo2PastaBackend::verify_aggregate(
            &agg,
            prev,
            &[p1, p2],
            &[commitments1, commitments2],
            &[1, 0],
            1,
            &[0u8; 32],
        ));
    }

    /// Regression: ensure the keygen circuit for unbalanced (n_in, n_out) shapes satisfies
    /// net_value=0 so keygen_vk succeeds. This catches the bug where the keygen circuit
    /// used amounts_in = [1; n_in], amounts_out = [1; n_out], which only works when n_in == n_out.
    /// The fix is in `ensure_keys` (halo2_pasta.rs:keygen). Each test here would panic with
    /// "keygen_vk failed: Frontend(Synthesis)" before the fix.
    #[test]
    fn test_keygen_unbalanced_2_1() {
        let ins = [30u64, 30u64];
        let outs = [60u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&a| create_commitment(a, &[0u8; 32])).collect();
        let in_blindings = [[0u8; 32], [0u8; 32]];
        let out_blindings = [[0u8; 32]];
        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs, &in_blindings, &out_blindings, &out_cms, 0,
        );
        assert!(Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    #[test]
    fn test_keygen_unbalanced_1_2() {
        let ins = [40u64];
        let outs = [20u64, 20u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&a| create_commitment(a, &[0u8; 32])).collect();
        let in_blindings = [[0u8; 32]];
        let out_blindings = [[0u8; 32], [0u8; 32]];
        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs, &in_blindings, &out_blindings, &out_cms, 0,
        );
        assert!(Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    #[test]
    fn test_keygen_unbalanced_3_1() {
        let ins = [10u64, 10u64, 10u64];
        let outs = [30u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&a| create_commitment(a, &[0u8; 32])).collect();
        let in_blindings = [[0u8; 32], [0u8; 32], [0u8; 32]];
        let out_blindings = [[0u8; 32]];
        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs, &in_blindings, &out_blindings, &out_cms, 0,
        );
        assert!(Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    #[test]
    fn test_keygen_unbalanced_1_3() {
        let ins = [30u64];
        let outs = [10u64, 10u64, 10u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&a| create_commitment(a, &[0u8; 32])).collect();
        let in_blindings = [[0u8; 32]];
        let out_blindings = [[0u8; 32], [0u8; 32], [0u8; 32]];
        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs, &in_blindings, &out_blindings, &out_cms, 0,
        );
        assert!(Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    /// Edge: n_in > 0, n_out = 0. The keygen fix sets public_amount = n_in to satisfy
    /// net_value=0. Without the fix this would panic in keygen_vk.
    #[test]
    fn test_keygen_unbalanced_2_0() {
        // (2 in, 0 out) shape: prove_conservation API requires at least 1 out,
        // so this tests the keygen path directly via ensure_keys.
        let (_vk, _pk) = ensure_keys(2, 0);
    }

    /// Edge: n_in = 0, n_out = 1. amounts_out = [0] (degenerate 64-bit decomposes to zeros).
    #[test]
    fn test_keygen_unbalanced_0_1() {
        let (_vk, _pk) = ensure_keys(0, 1);
    }

    /// Edge: n_in = 0, n_out = 0. Empty keygen, all-zero instance.
    #[test]
    fn test_keygen_unbalanced_0_0() {
        let (_vk, _pk) = ensure_keys(0, 0);
    }

    #[test]
    fn test_crs_loaded_or_generated() {
        let params = ensure_params();
        assert!(params.k() >= PROVING_K);
    }

    #[test]
    fn test_commitment_consistency() {
        let blinding = [0x99u8; 32];
        let cm1 = create_commitment(42, &blinding);
        let cm2 = create_commitment(42, &blinding);
        assert_eq!(cm1, cm2);
        let cm3 = create_commitment(43, &blinding);
        assert_ne!(cm1, cm3);
        let cm4 = create_commitment(42, &[0xFFu8; 32]);
        assert_ne!(cm1, cm4);
    }

    #[test]
    fn test_full_conservation_with_commitments_binding() {
        let in_blindings = vec![[0x11u8; 32], [0x22u8; 32]];
        let out_blindings = vec![[0x33u8; 32], [0x44u8; 32]];
        let ins = [100u64, 50u64];
        let outs = [80u64, 70u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().enumerate().map(|(i, &amt)| {
            create_commitment(amt, &out_blindings[i])
        }).collect();

        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs,
            &[in_blindings[0], in_blindings[1]],
            &[out_blindings[0], out_blindings[1]],
            &out_cms, 0,
        );
        assert!(Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    #[test]
    fn test_commitment_binding_rejects_tampered() {
        let out_cms = vec![[0x11u8; 32], [0x22u8; 32]];
        let wrong_cms = vec![[0x01u8; 32], [0x02u8; 32]];
        let proof = make_proof(&[100, 50], &[80, 70], &out_cms, 0);
        assert!(!Halo2PastaBackend::verify_conservation(&proof, &wrong_cms, 0));
    }

    #[test]
    fn test_aggregate_with_commitments_binding() {
        let blinding = [0xAAu8; 32];
        let ins = [30u64, 30u64];
        let outs = [60u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&amt| {
            create_commitment(amt, &blinding)
        }).collect();
        let proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs,
            &[blinding, blinding],
            &[blinding],
            &out_cms, 0,
        );

        let prev = b"aetheris_aggregate_v1_genesis_test";
        let result = Halo2PastaBackend::aggregate_proofs(
            prev,
            &[proof.clone()],
            &[out_cms.clone()],
            &[0],
            1,
            &[0u8; 32],
        );
        assert!(result.is_ok(), "aggregate_proofs should succeed with valid proofs");
    }

    #[test]
    fn test_proof_tamper_detection() {
        let blinding = [0xBBu8; 32];
        let ins = [100u64];
        let outs = [100u64];
        let out_cms: Vec<[u8; 32]> = outs.iter().map(|&amt| {
            create_commitment(amt, &blinding)
        }).collect();
        let mut proof = Halo2PastaBackend::prove_conservation(
            &ins, &outs,
            &[blinding],
            &[blinding],
            &out_cms, 0,
        );
        if let Some(last) = proof.last_mut() {
            *last ^= 0xFF;
        }
        assert!(!Halo2PastaBackend::verify_conservation(&proof, &out_cms, 0));
    }

    #[test]
    fn test_range_rejects_overflow_amount() {
        use halo2_proofs::dev::MockProver;

        struct OverflowCircuit;
        impl Circuit<Fq> for OverflowCircuit {
            type Config = ValueConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { OverflowCircuit }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                <ValueConservationCircuit as Circuit<Fq>>::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let large = Fq::from(u64::MAX) + Fq::one();
                let inv_2 = Fq::from(2).invert().unwrap();
                layouter.assign_region(|| "overflow_range", |mut region| {
                    let mut offset = 0;
                    region.assign_advice(|| "z_0_overflow", config.advice[0], offset, || Value::known(large))?;
                    region.assign_advice(|| "z_0_bit", config.advice[1], offset, || Value::known(Fq::zero()))?;
                    let mut z_prev = large;
                    for _ in 0..64 {
                        offset += 1;
                        config.s_running_sum.enable(&mut region, offset)?;
                        let bit = Fq::zero();
                        let z_cur = (z_prev - bit) * inv_2;
                        region.assign_advice(|| "z_cur", config.advice[0], offset, || Value::known(z_cur))?;
                        region.assign_advice(|| "bit", config.advice[1], offset, || Value::known(bit))?;
                        z_prev = z_cur;
                    }
                    offset += 1;
                    config.s_zero_check.enable(&mut region, offset)?;
                    region.assign_advice(|| "z_64_overflow", config.advice[0], offset, || Value::known(z_prev))?;
                    region.assign_advice(|| "zero_ref", config.advice[2], offset, || Value::known(Fq::ZERO))?;
                    Ok(())
                })
            }
        }

        let prover = MockProver::run(11, &OverflowCircuit, vec![vec![]]).unwrap();
        assert!(prover.verify().is_err(), "overflow amount should be rejected by constraint");
    }

    #[test]
    fn test_value_conservation_proof_verifies() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[42], &[42], &commitments, 0);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, 0));
    }

    // ─── ZkProverSystem::prove_vdf / verify_vdf (real Wesolowski VDF) ──────
    //
    // Phase 1.6: trait methods are no longer stubs; they delegate to
    // `aetheris_crypto::VDF::solve` / `VDF::verify` (default trait impl).
    // These tests lock in the contract: prove→verify roundtrip; wrong
    // difficulty/seed/corruption must reject; the old stub output must
    // not bypass verify.
    //
    // PASTA_VDF_DIFF=10 matches the FFI tests' AETHERIS_VDF_DIFFICULTY=10
    // env-var value (~1s per solve). The trait method is a pure function
    // `(seed, difficulty) -> (result, proof)`, so we use a local constant
    // rather than the env-var pattern (which would be a layering violation
    // for a library crate).

    const PASTA_VDF_DIFF: u64 = 10;

    #[test]
    fn test_pasta_backend_prove_vdf_roundtrip() {
        let seed = b"pasta_vdf_roundtrip_seed";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        assert!(
            Halo2PastaBackend::verify_vdf(&result, &proof, seed, PASTA_VDF_DIFF),
            "prove→verify roundtrip must succeed"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_wrong_difficulty() {
        let seed = b"pasta_vdf_wrong_diff_seed";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        assert!(
            !Halo2PastaBackend::verify_vdf(&result, &proof, seed, PASTA_VDF_DIFF + 10),
            "proof generated at D=10 must fail verification at D=20 (difficulty binding)"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_wrong_seed() {
        let seed_a = b"pasta_vdf_seed_A_xxxxxxxxxxxxxx";
        let seed_b = b"pasta_vdf_seed_B_xxxxxxxxxxxxxx";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed_a, PASTA_VDF_DIFF);
        assert!(
            !Halo2PastaBackend::verify_vdf(&result, &proof, seed_b, PASTA_VDF_DIFF),
            "proof generated with seed A must fail verification with seed B"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_difficulty_zero() {
        let seed = b"pasta_vdf_d0_seed";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed, 0);
        assert!(
            Halo2PastaBackend::verify_vdf(&result, &proof, seed, 0),
            "difficulty-0 roundtrip must succeed (no iterations)"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_bypass_rejected() {
        let seed = b"pasta_vdf_bypass_seed";
        assert!(
            !Halo2PastaBackend::verify_vdf(
                b"vdf_zkp_pasta_v1_simulated",
                b"vdf_zkp_pasta_v1_simulated",
                seed,
                PASTA_VDF_DIFF
            ),
            "old 18-byte stub output must not bypass verify"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_corrupted_proof() {
        let seed = b"pasta_vdf_corrupt_seed";
        let (result, mut proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        proof[0] ^= 0xFF;
        assert!(
            !Halo2PastaBackend::verify_vdf(&result, &proof, seed, PASTA_VDF_DIFF),
            "length-prefix-corrupted proof must fail verification via Form::from_bytes rejection"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_empty_inputs_rejected() {
        let seed = b"pasta_vdf_empty_seed";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        assert!(
            !Halo2PastaBackend::verify_vdf(&[], &proof, seed, PASTA_VDF_DIFF),
            "empty result must reject"
        );
        assert!(
            !Halo2PastaBackend::verify_vdf(&result, &[], seed, PASTA_VDF_DIFF),
            "empty proof must reject"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_determinism() {
        let seed = b"pasta_vdf_determinism_seed";
        let (r1, p1) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        let (r2, p2) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        assert_eq!(r1, r2, "same seed + difficulty must produce identical result");
        assert_eq!(p1, p2, "same seed + difficulty must produce identical proof");
    }

    #[test]
    fn test_pasta_backend_prove_vdf_wire_format_size() {
        let seed = b"pasta_vdf_size_seed";
        let (result, proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        assert!(result.len() > 100, "result must be class-group-sized, got {}", result.len());
        assert!(proof.len() > 100, "proof must be class-group-sized, got {}", proof.len());
        assert!(
            !result.starts_with(b"vdf_zkp_"),
            "result must not be the historical stub prefix"
        );
        assert!(
            !proof.starts_with(b"vdf_zkp_"),
            "proof must not be the historical stub prefix"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_empty_seed() {
        let (result, proof) = Halo2PastaBackend::prove_vdf(b"", PASTA_VDF_DIFF);
        assert!(
            Halo2PastaBackend::verify_vdf(&result, &proof, b"", PASTA_VDF_DIFF),
            "empty seed roundtrip must succeed"
        );
    }

    #[test]
    fn test_pasta_backend_prove_vdf_bypass_rejected_comprehensive() {
        let seed = b"pasta_vdf_bypass_comprehensive_seed";
        let bypass_attempts: &[&[u8]] = &[
            b"vdf_zkp_pasta_v1_simulated",
            b"vdf_zkp_pasta_v1_simulated_real_data_appended_xxxxxxxxxxxx",
            b"vdf_zkp_",
            b"vdf_zkp_v1_simulated",
        ];
        for (i, attempt) in bypass_attempts.iter().enumerate() {
            assert!(
                !Halo2PastaBackend::verify_vdf(attempt, attempt, seed, PASTA_VDF_DIFF),
                "bypass attempt #{} ({:?}) must be rejected by verify", i, attempt
            );
        }
    }

    #[test]
    fn test_pasta_backend_prove_vdf_deep_corruption_rejected() {
        // Phase 1.7: now that aetheris-crypto::VDF::verify rejects
        // mismatched-discriminant forms at the boundary (vdf.rs:110-117),
        // we can corrupt a byte DEEP in the form encoding (not just the
        // length prefix) without triggering the pre-existing
        // classgroup.rs:112 debug_assert_eq! panic.
        let seed = b"pasta_vdf_deep_corrupt_seed";
        let (result, mut proof) = Halo2PastaBackend::prove_vdf(seed, PASTA_VDF_DIFF);
        let deep_idx = proof.len() / 2;
        proof[deep_idx] ^= 0xFF;
        assert!(
            !Halo2PastaBackend::verify_vdf(&result, &proof, seed, PASTA_VDF_DIFF),
            "deep-form-encoding corruption must be rejected at discriminant boundary (no panic)"
        );
    }
}

// ─── Synthetic IFFT roundtrip tests ────────────────────────────────────────
//
// The prover pipeline: evaluate_h → f_coset → divide_by_vanishing_poly
// → h_coset → extended_to_coeff → h_poly.
//
// These tests isolate the IFFT/extended_to_coeff step from the circuit,
// using known polynomials evaluated at the extended coset.

#[cfg(test)]
mod synthetic_roundtrip_tests {
    use super::*;
    use halo2_proofs::halo2curves::ff::WithSmallOrderMulGroup;
    use halo2_backend::poly::{EvaluationDomain, Coeff, ExtendedLagrangeCoeff, Polynomial};

    /// Evaluate a polynomial (coefficient slice) at a point using Horner.
    fn horner<F: Field>(coeff: &[F], point: F) -> F {
        let mut acc = F::ZERO;
        for c in coeff.iter().rev() {
            acc = acc * point + c;
        }
        acc
    }

    #[test]
    fn test_fft_roundtrip_length_n() {
        // coeff_to_extended → extended_to_coeff for a length‑n polynomial
        let domain = EvaluationDomain::<Fq>::new(3, PROVING_K);
        let n = 1 << domain.k();
        let extended_n = domain.extended_len();
        let mut rng = OsRng;

        // Random degree‑(n-1) polynomial
        let coeff: Vec<Fq> = (0..n).map(|_| Fq::random(&mut rng)).collect();
        let p_coeff: Polynomial<Fq, Coeff> = domain.coeff_from_vec(coeff.clone());

        // Roundtrip
        let p_coset = domain.coeff_to_extended(p_coeff);
        let back = domain.extended_to_coeff(p_coset);

        assert_eq!(back.len(), extended_n, "extended_to_coeff length mismatch");
        for (i, (&a, &b)) in coeff.iter().zip(back.iter()).enumerate() {
            assert_eq!(a, b, "Coeff mismatch at index {}", i);
        }
        for i in n..extended_n {
            assert!(
                back[i].is_zero_vartime(),
                "Upper coefficient at {} should be zero, got {:?}",
                i, back[i]
            );
        }
        eprintln!("[SYNTH] test_fft_roundtrip_length_n PASSED (n={}, ext_n={})", n, extended_n);
    }

    #[test]
    fn test_extended_to_coeff_low_degree() {
        // Evaluate a known degree‑50 polynomial at the 8192 coset points,
        // then run extended_to_coeff and verify the coefficients come back.
        let domain = EvaluationDomain::<Fq>::new(3, PROVING_K);
        let n = 1 << domain.k();
        let extended_n = domain.extended_len();
        let mut rng = OsRng;

        let degree = 50usize;
        let mut h_true = vec![Fq::ZERO; extended_n];
        for i in 0..=degree {
            h_true[i] = Fq::random(&mut rng);
        }

        let zeta = Fq::ZETA;
        let omega_ext = domain.get_extended_omega();

        // Evaluate h_true at every coset point
        let mut h_coset = Vec::with_capacity(extended_n);
        for i in 0..extended_n {
            let point = zeta * omega_ext.pow_vartime([i as u64, 0, 0, 0]);
            h_coset.push(horner(&h_true, point));
        }

        let h_coset_poly = Polynomial::<Fq, ExtendedLagrangeCoeff> {
            values: h_coset,
            _marker: std::marker::PhantomData,
        };
        let h_back = domain.extended_to_coeff(h_coset_poly);

        assert_eq!(h_back.len(), extended_n);

        let mut max_spurious = 0usize;
        for i in 0..extended_n {
            if i <= degree {
                assert_eq!(
                    h_back[i], h_true[i],
                    "Coeff mismatch at index {} (should match deg-{} poly)",
                    i, degree
                );
            } else {
                if !h_back[i].is_zero_vartime() {
                    max_spurious = i;
                    eprintln!("[SYNTH] SPURIOUS: h_back[{}] = {:?} (should be zero, deg={})",
                        i, h_back[i], degree);
                }
            }
        }
        if max_spurious > 0 {
            panic!(
                "extended_to_coeff returned non-zero at index {} (degree {} polynomial). \
                 Max allowed degree is {}, poly length is {}",
                max_spurious, degree, degree, extended_n
            );
        }
        eprintln!("[SYNTH] test_extended_to_coeff_low_degree PASSED (n={}, deg={}, ext_n={})",
            n, degree, extended_n);
    }

    #[test]
    fn test_divide_then_ifft_roundtrip() {
        // Full pipeline simulation with a known low‑degree polynomial:
        //   1. h_true (known coeff, deg <= n*qpd)
        //   2. f_coeff = h_true * (X^n - 1)
        //   3. Evaluate f at coset points → f_coset
        //   4. divide_by_vanishing_poly → h_coset
        //   5. extended_to_coeff → h_back
        //   6. Compare h_back with h_true.
        let domain = EvaluationDomain::<Fq>::new(3, PROVING_K);
        let n = 1 << domain.k();
        let max_h_deg = n * domain.get_quotient_poly_degree() as usize; // 4096
        let extended_n = domain.extended_len();
        let mut rng = OsRng;

        // Use degree 200 to keep things fast while still testing the pipeline
        let h_deg = 200usize;
        let mut h_true = vec![Fq::ZERO; max_h_deg];
        for i in 0..=h_deg {
            h_true[i] = Fq::random(&mut rng);
        }

        // f(X) = h(X) * (X^n - 1) = h(X)*X^n - h(X)
        let mut f_coeff = vec![Fq::ZERO; max_h_deg + n as usize];
        for i in 0..max_h_deg {
            f_coeff[i] -= h_true[i];
            f_coeff[i + n as usize] += h_true[i];
        }

        let zeta = Fq::ZETA;
        let omega_ext = domain.get_extended_omega();

        // Evaluate f at each coset point
        let mut f_coset = Vec::with_capacity(extended_n);
        for i in 0..extended_n {
            let point = zeta * omega_ext.pow_vartime([i as u64, 0, 0, 0]);
            f_coset.push(horner(&f_coeff, point));
        }

        // Create Polynomial<ExtendedLagrangeCoeff> for divide_by_vanishing_poly
        let f_coset_poly = Polynomial::<Fq, ExtendedLagrangeCoeff> {
            values: f_coset,
            _marker: std::marker::PhantomData,
        };

        // Divide by X^n - 1 (pointwise on coset)
        let h_coset_poly = domain.divide_by_vanishing_poly(f_coset_poly);

        // IFFT back to coefficients
        let h_back = domain.extended_to_coeff(h_coset_poly);

        assert_eq!(h_back.len(), extended_n);

        let mut max_spurious = 0usize;
        for i in 0..extended_n.min(max_h_deg) {
            if i <= h_deg {
                assert_eq!(
                    h_back[i], h_true[i],
                    "h_back[{}] mismatch (should match h_true[{}])", i, i
                );
            } else {
                if !h_back[i].is_zero_vartime() {
                    max_spurious = i;
                    eprintln!("[SYNTH] SPURIOUS: h_back[{}] = {:?} (should be zero, h_deg={})",
                        i, h_back[i], h_deg);
                }
            }
        }
        if max_spurious > 0 {
            panic!(
                "Pipeline produced spurious coefficient at h_back[{}] (h_deg={}). \
                 extended_n={}, max_h_deg={}",
                max_spurious, h_deg, extended_n, max_h_deg
            );
        }
        eprintln!("[SYNTH] test_divide_then_ifft_roundtrip PASSED (h_deg={}, ext_n={})",
            h_deg, extended_n);
    }

    #[test]
    fn test_extended_to_coeff_high_degree() {
        // Same as test_extended_to_coeff_low_degree but with h of degree 4093
        // (matching the actual circuit's h degree). This verifies the IFFT is
        // correct at the full expected degree.
        let domain = EvaluationDomain::<Fq>::new(3, PROVING_K);
        let extended_n = domain.extended_len();
        let mut rng = OsRng;

        let h_deg = 4093usize;
        let mut h_true = vec![Fq::ZERO; extended_n];
        for i in 0..=h_deg {
            h_true[i] = Fq::random(&mut rng);
        }

        let zeta = Fq::ZETA;
        let omega_ext = domain.get_extended_omega();

        let mut h_coset = Vec::with_capacity(extended_n);
        for i in 0..extended_n {
            let point = zeta * omega_ext.pow_vartime([i as u64, 0, 0, 0]);
            h_coset.push(horner(&h_true, point));
        }

        let h_coset_poly = Polynomial::<Fq, ExtendedLagrangeCoeff> {
            values: h_coset,
            _marker: std::marker::PhantomData,
        };
        let h_back = domain.extended_to_coeff(h_coset_poly);

        let mut max_spurious = 0usize;
        let mut max_spurious_val = Fq::ZERO;
        for i in 0..extended_n {
            if i <= h_deg {
                assert_eq!(
                    h_back[i], h_true[i],
                    "Coeff mismatch at index {} (deg {} poly)", i, h_deg
                );
            } else {
                if !h_back[i].is_zero_vartime() {
                    max_spurious = i;
                    max_spurious_val = h_back[i];
                }
            }
        }
        if max_spurious > 0 {
            panic!(
                "HIGH-DEGREE IFFT FAILED: h_back[{}] = {:?} (non-zero after deg {})",
                max_spurious, max_spurious_val, h_deg
            );
        }
        eprintln!("[SYNTH] test_extended_to_coeff_high_degree PASSED (h_deg={})", h_deg);
    }

    #[test]
    fn test_full_pipeline_high_degree() {
        // Full f→h pipeline with h_deg=4093, f_deg=6141 (matching circuit)
        let domain = EvaluationDomain::<Fq>::new(3, PROVING_K);
        let n = 1 << domain.k();
        let max_h_deg = n * domain.get_quotient_poly_degree() as usize;
        let extended_n = domain.extended_len();
        let mut rng = OsRng;

        let h_deg = 4093usize;
        let mut h_true = vec![Fq::ZERO; max_h_deg];
        for i in 0..=h_deg {
            h_true[i] = Fq::random(&mut rng);
        }

        // f(X) = h(X) * (X^n - 1)
        let mut f_coeff = vec![Fq::ZERO; max_h_deg + n as usize];
        for i in 0..max_h_deg {
            f_coeff[i] -= h_true[i];
            f_coeff[i + n as usize] += h_true[i];
        }

        let zeta = Fq::ZETA;
        let omega_ext = domain.get_extended_omega();

        let mut f_coset = Vec::with_capacity(extended_n);
        for i in 0..extended_n {
            let point = zeta * omega_ext.pow_vartime([i as u64, 0, 0, 0]);
            f_coset.push(horner(&f_coeff, point));
        }

        let f_coset_poly = Polynomial::<Fq, ExtendedLagrangeCoeff> {
            values: f_coset,
            _marker: std::marker::PhantomData,
        };
        let h_coset_poly = domain.divide_by_vanishing_poly(f_coset_poly);
        let h_back = domain.extended_to_coeff(h_coset_poly);

        let mut max_spurious = 0usize;
        for i in 0..extended_n.min(max_h_deg) {
            if i <= h_deg {
                assert_eq!(
                    h_back[i], h_true[i],
                    "h_back[{}] mismatch in full pipeline (h_deg={})", i, h_deg
                );
            } else {
                if !h_back[i].is_zero_vartime() {
                    max_spurious = i;
                }
            }
        }
        if max_spurious > 0 {
            panic!(
                "FULL PIPELINE HIGH-DEG FAILED: h_back[{}] non-zero (h_deg={}, should be zero)",
                max_spurious, h_deg
            );
        }
        eprintln!("[SYNTH] test_full_pipeline_high_degree PASSED (h_deg={})", h_deg);
    }
}
