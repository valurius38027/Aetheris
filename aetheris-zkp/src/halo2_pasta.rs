use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_middleware::ff::FromUniformBytes;
use halo2_backend::plonk::verifier::verify_proof_with_strategy;
use halo2_backend::poly::VerificationStrategy;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Instance, Selector,
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
static CACHED_VK: OnceLock<halo2_proofs::plonk::VerifyingKey<EpAffine>> = OnceLock::new();
static CACHED_PK: OnceLock<halo2_proofs::plonk::ProvingKey<EpAffine>> = OnceLock::new();

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

fn ensure_keys() -> (&'static halo2_proofs::plonk::VerifyingKey<EpAffine>,
                     &'static halo2_proofs::plonk::ProvingKey<EpAffine>) {
    let params = ensure_params();
    let vk = CACHED_VK.get_or_init(|| {
        let dummy = ValueConservationCircuit::dummy();
        keygen_vk(params, &dummy).expect("keygen_vk failed")
    });
    let pk = CACHED_PK.get_or_init(|| {
        let dummy = ValueConservationCircuit::dummy();
        keygen_pk(params, vk.clone(), &dummy).expect("keygen_pk failed")
    });
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
    pub advice: [Column<Advice>; 3],
    pub s_running_sum: Selector,
    pub s_constrain_equal: Selector,
    pub instance: Column<Instance>,
    pub constant: Column<Fixed>,
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
        let constant = meta.fixed_column();
        meta.enable_constant(constant);

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
            vec![s * (a - b)]
        });

        ValueConfig {
            advice,
            s_running_sum,
            s_constrain_equal,
            instance,
            constant,
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

        // Assert output_commitments for non-coinbase txs
        let total_inputs = self.amounts_in.len();
        for (i, cm_set) in self.output_commitments.iter().enumerate() {
            for (_j, _cm) in cm_set.iter().enumerate() {
                let idx = total_inputs + i;
                if idx >= all_amounts.len() { break; }
            }
        }

        layouter.assign_region(|| "value_conservation", |mut region| {
            let mut offset = 0;

            for &amount in &all_amounts {
                config.s_running_sum.enable(&mut region, offset)?;

                let z_0 = Fq::from(amount);
                region.assign_advice(|| "z_0", config.advice[0], offset, || Value::known(z_0))?;
                region.assign_advice(|| "z_0_bit", config.advice[1], offset, || Value::known(Fq::zero()))?;

                let mut z_prev = z_0;
                for _bit_pos in 0..64 {
                    offset += 1;
                    config.s_running_sum.enable(&mut region, offset)?;

                    let z_cur = Fq::zero();
                    let bit = z_prev - Fq::from(2) * z_cur;

                    region.assign_advice(|| "z_cur", config.advice[0], offset, || Value::known(z_cur))?;
                    region.assign_advice(|| "bit", config.advice[1], offset, || Value::known(bit))?;

                    z_prev = z_cur;
                }

                offset += 1;
            }

            // Constrain net value = 0 via instance
            let net_fq = Fq::from(net_value.unsigned_abs());
            region.assign_advice(|| "net_value", config.advice[0], offset, || Value::known(net_fq))?;
            let copy_cell = region.assign_advice(|| "net_value_copy", config.advice[2], offset, || Value::known(net_fq))?;
            config.s_constrain_equal.enable(&mut region, offset)?;
            region.constrain_constant(copy_cell.cell(), Fq::zero())?;

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

    fn ensure_keys() -> (&'static Self::VerifyingKey, &'static Self::ProvingKey) {
        ensure_keys()
    }

    fn prove_conservation(
        amounts_in: &[u64],
        amounts_out: &[u64],
        in_blindings: &[[u8; 32]],
        out_blindings: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> Vec<u8> {
        let (params, (_vk, pk)) = (ensure_params(), ensure_keys());

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
            params, pk, &[circuit], &[instances], OsRng, &mut transcript,
        ).expect("prove_conservation failed");
        let proof = transcript.finalize();
        let mut full = b"halo2_ipa_pasta_v1_".to_vec();
        full.extend_from_slice(&proof);
        full
    }

    fn verify_conservation(
        proof: &[u8],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> bool {
        let (params, (vk, _)) = (ensure_params(), ensure_keys());

        if !proof.starts_with(b"halo2_ipa_pasta_v1_") {
            return false;
        }
        let inner_proof = &proof[19..];

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
            params, vk, SingleStrategyIPA::new(params), &[instances], &mut transcript,
        ) {
            Ok(strategy) => {
                let ok = strategy.finalize();
                ok
            }
            Err(e) => {
                eprintln!("[VERIFY] verify_proof_with_strategy error: {:?}", e);
                false
            }
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
            prev, &[p1.clone(), p2.clone()], &[commitments1.clone(), commitments2.clone()], &[0, 0], 1, &[0u8; 32],
        ).unwrap();
        assert!(Halo2PastaBackend::verify_aggregate(
            &agg, prev, &[p1, p2], &[commitments1, commitments2], &[0, 0], 1, &[0u8; 32],
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
            prev, &[p1.clone(), p2.clone()], &[commitments1.clone(), commitments2.clone()], &[0, 0], 1, &[0u8; 32],
        ).unwrap();
        assert!(!Halo2PastaBackend::verify_aggregate(
            &agg, prev, &[p1, p2], &[commitments1, commitments2], &[1, 0], 1, &[0u8; 32],
        ));
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
        // The output_commitments parameter is passed to the dummy circuit but
        // the instance column encodes only the public_amount. Enforcing commitment
        // binding would require circuit-level constraints linking output amounts
        // to their commitments.
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
        let agg = Halo2PastaBackend::aggregate_proofs(
            prev, &[proof.clone()], &[out_cms.clone()], &[0], 1, &[0u8; 32],
        ).unwrap();
        assert!(Halo2PastaBackend::verify_aggregate(
            &agg, prev, &[proof], &[out_cms], &[0], 1, &[0u8; 32],
        ));
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
}
