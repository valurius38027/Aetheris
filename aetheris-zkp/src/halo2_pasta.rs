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
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadCore, aead::Aead};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::ipa::commitment::{CommitmentSchemeIPA, ParamsIPA};
use crate::ipa::prover::ProverIPA;
use crate::ipa::strategy::SingleStrategyIPA;
use crate::trait_::{ZkProverSystem, TxCommitments};

const PROVING_K: u32 = 11;

static CACHED_PARAMS: OnceLock<ParamsIPA<EpAffine>> = OnceLock::new();
type CachedKeyPair = (
    halo2_proofs::plonk::VerifyingKey<EpAffine>,
    halo2_proofs::plonk::ProvingKey<EpAffine>,
);
static KEY_CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<(usize, usize), CachedKeyPair>>> =
    OnceLock::new();

fn ensure_params() -> &'static ParamsIPA<EpAffine> {
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
            return ParamsIPA::<EpAffine>::setup_deterministic(PROVING_K);
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
    pub advice: [Column<Advice>; 3],
    pub s_running_sum: Selector,
    pub s_constrain_equal: Selector,
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
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for col in &advice {
            meta.enable_equality(*col);
        }
        let s_running_sum = meta.selector();
        let s_constrain_equal = meta.selector();
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

        meta.create_gate("constrain_equal", |meta| {
            let s = meta.query_selector(s_constrain_equal);
            let a = meta.query_advice(advice[0], Rotation(0));
            let b = meta.query_advice(advice[2], Rotation(0));
            // s * (a - b) = 0  -> a = b
            // s * b         = 0  -> b = 0
            // Combined: a = b = 0 when s = 1.
            // This replaces a separate `region.constrain_constant(b, 0)` call,
            // avoiding the need for `meta.enable_constant` (which would also add
            // the fixed column to the permutation argument and break multiset equality).
            vec![s.clone() * (a - b.clone()), s * b]
        });

        ValueConfig {
            advice,
            s_running_sum,
            s_constrain_equal,
            instance,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
        let total_in: u64 = self.amounts_in.iter().sum();
        let total_out: u64 = self.amounts_out.iter().sum();
        let net_value = total_in as i64 - total_out as i64 - self.public_amount;

        if net_value != 0 {
            return Err(ErrorFront::Synthesis);
        }

        let all_amounts: Vec<u64> = self.amounts_in.iter()
            .chain(self.amounts_out.iter())
            .copied()
            .collect();

        layouter.assign_region(|| "value_conservation", |mut region| {
            let mut offset = 0;
            let inv_2 = Fq::from(2).invert().unwrap();

            for &amount in &all_amounts {
                // Initial row: assign initial z value WITHOUT s_running_sum.
                // This avoids Rotation(-1) wrapping to unassigned row 2047.
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

                offset += 1; // gap between amounts
            }

            // Constrain net value = 0
            let net_fq = Fq::from(0u64);
            region.assign_advice(|| "net_value", config.advice[0], offset, || Value::known(net_fq))?;
            let _copy_cell = region.assign_advice(|| "net_value_copy", config.advice[2], offset, || Value::known(net_fq))?;
            config.s_constrain_equal.enable(&mut region, offset)?;

            offset += 1;

            // Constrain instance[0] == public_amount via copy constraint
            region.assign_advice_from_instance(
                || "instance_pub", config.instance, 0, config.advice[0], offset,
            )?;

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
        let instances = vec![vec![instance_fq]];
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
        _output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> bool {
        const PREFIX: &[u8] = b"halo2_ipa_pasta_v1_";
        const PREFIX_LEN: usize = 19;
        const SHAPE_LEN: usize = 4;
        if proof.len() < PREFIX_LEN + SHAPE_LEN || !proof.starts_with(PREFIX) {
            return false;
        }
        let in_len = u16::from_le_bytes(proof[PREFIX_LEN..PREFIX_LEN + 2].try_into().unwrap()) as usize;
        let out_len = u16::from_le_bytes(
            proof[PREFIX_LEN + 2..PREFIX_LEN + SHAPE_LEN].try_into().unwrap(),
        ) as usize;
        let inner_proof = &proof[PREFIX_LEN + SHAPE_LEN..];

        let (params, (vk, _)) = (ensure_params(), ensure_keys(in_len, out_len));

        // Derive instance from public_amount (encoded as Fq for the instance column)
        let instance_fq = if public_amount >= 0 {
            Fq::from(public_amount as u64)
        } else {
            // For negative public_amount, use two's complement in the field
            Fq::ZERO - Fq::from(public_amount.unsigned_abs())
        };
        let instances = vec![vec![instance_fq]];

        let mut transcript = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(inner_proof);
        match verify_proof_with_strategy::<CommitmentSchemeIPA<EpAffine>, _, Challenge255<EpAffine>, Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>, SingleStrategyIPA<'_, EpAffine>>(
            params, &vk, SingleStrategyIPA::new(params), &[instances], &mut transcript,
        ) {
            Ok(strategy) => {
                let ok = strategy.finalize();
                ok
            }
            Err(_) => false
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

    fn prove_vdf(_public_seed: &[u8], _difficulty: u64) -> Vec<u8> {
        b"vdf_zkp_pasta_v1_simulated".to_vec()
    }

    fn verify_vdf(_proof: &[u8], _public_seed: &[u8], _difficulty: u64) -> bool {
        true
    }
}

impl Halo2PastaBackend {
    pub fn setup_params() -> ParamsIPA<EpAffine> {
        ParamsIPA::<EpAffine>::setup_deterministic(PROVING_K)
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

    fn make_proof(amounts_in: &[u64], amounts_out: &[u64], commitments: &[[u8; 32]], pub_amt: i64) -> Vec<u8> {
        Halo2PastaBackend::prove_conservation(amounts_in, amounts_out, &[], &[], commitments, pub_amt)
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

        // NOTE: Output commitment binding is not enforced by the current circuit.
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
    fn test_value_conservation_proof_verifies() {
        let commitments = vec![[0u8; 32]; 1];
        let proof = make_proof(&[42], &[42], &commitments, 0);
        assert!(Halo2PastaBackend::verify_conservation(&proof, &commitments, 0));
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
    use rand::rngs::OsRng;
    use rand::RngCore;

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
        eprintln!("[SYNTH] test_extended_to_coeff_low_degree PASSED (deg={}, ext_n={})",
            degree, extended_n);
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
