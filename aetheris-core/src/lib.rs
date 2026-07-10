use serde::{Deserialize, Serialize};

pub type Amount = u64;
pub type Hash = [u8; 32];
pub type Nullifier = Hash;
pub type Commitment = Hash;
pub type AssetId = Hash;
pub type NoteRoot = Hash;

pub const AET_ASSET_ID: AssetId = [0u8; 32];
pub const PROOF_SYSTEM_LEGACY_CONSERVATION: u16 = 0;
pub const PROOF_SYSTEM_CANONICAL_SHIELDED_V1: u16 = 1;

pub const VDF_DIFFICULTY: u64 = 1_600_000;
pub const TARGET_BLOCK_TIME: u64 = 10; // Target 10 seconds per block
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 10; // Adjust difficulty every 10 blocks
pub const MAX_VDF_SPEED: u64 = 5_000_000; // Max 5M iterations/sec (Anti-acceleration threshold)
pub const MAX_INPUTS: usize = 5;
pub const MAX_OUTPUTS: usize = 5;
// EXPECTED_GENESIS_HASH — recompute after changing create_genesis_block.
// Fair launch genesis: empty block (no mint/transfer transactions).
// Recompute with: cargo test -p aetheris-ffi --lib test_genesis_hash_locked -- --test-threads=1
pub const EXPECTED_GENESIS_HASH: &str = "cd930c8e33305255c09bbf389ccf14aec4b825ccbd416bec46db49ebaa1429e1";

const NOTE_COMMITMENT_DOMAIN: &[u8] = b"AETHERIS_NOTE_COMMITMENT_V1";
const NULLIFIER_DOMAIN: &[u8] = b"AETHERIS_NULLIFIER_V1";

/// Computes the canonical note commitment used by transaction outputs.
///
/// The field order is consensus-critical and intentionally includes all
/// immutable note plaintext fields plus the separate commitment blinding.
/// Future circuit work must reproduce this transcript inside the proof system
/// before Phase 2 can mark output commitment binding as closed.
pub fn canonical_note_commitment(note: &NotePlaintext, blinding: &[u8; 32]) -> Commitment {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NOTE_COMMITMENT_DOMAIN);
    hasher.update(&note.amount.to_le_bytes());
    hasher.update(&note.asset_id);
    hasher.update(&note.owner);
    hasher.update(&note.rho);
    hasher.update(&note.rseed);
    hasher.update(&(note.memo.len() as u64).to_le_bytes());
    hasher.update(&note.memo);
    hasher.update(blinding);
    hasher.finalize().into()
}

/// Computes the canonical nullifier for an input note witness.
///
/// The nullifier binds the already-committed note, the wallet's nullifier key,
/// and the note tree position. Nodes still enforce uniqueness against chain
/// state, while the ZK transaction proof must eventually constrain this same
/// transcript so arbitrary public nullifiers cannot be supplied.
pub fn canonical_nullifier(
    note_commitment: &Commitment,
    nullifier_key: &[u8; 32],
    merkle_position: u64,
) -> Nullifier {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NULLIFIER_DOMAIN);
    hasher.update(note_commitment);
    hasher.update(nullifier_key);
    hasher.update(&merkle_position.to_le_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotePlaintext {
    pub amount: Amount,
    pub asset_id: AssetId,
    pub owner: [u8; 32],
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
    pub memo: Vec<u8>,
}

impl NotePlaintext {
    /// Domain-separated canonical note commitment for the current host-side
    /// protocol model. The ZK circuit closure work must constrain the same
    /// field order so every public output commitment commits to the private
    /// note fields rather than only to amount/blinding.
    pub fn commitment(&self, blinding: &[u8; 32]) -> Commitment {
        canonical_note_commitment(self, blinding)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteWitness {
    pub note: NotePlaintext,
    pub blinding: [u8; 32],
    pub nullifier_key: [u8; 32],
    pub merkle_path: Vec<Hash>,
    pub merkle_position: u64,
}

impl NoteWitness {
    pub fn commitment(&self) -> Commitment {
        self.note.commitment(&self.blinding)
    }

    pub fn nullifier(&self) -> Nullifier {
        canonical_nullifier(&self.commitment(), &self.nullifier_key, self.merkle_position)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputNoteWitness {
    pub note: NotePlaintext,
    pub blinding: [u8; 32],
}

impl OutputNoteWitness {
    pub fn commitment(&self) -> Commitment {
        self.note.commitment(&self.blinding)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionWitness {
    pub inputs: Vec<NoteWitness>,
    pub outputs: Vec<OutputNoteWitness>,
}

impl TransactionWitness {
    pub fn input_nullifiers(&self) -> Vec<Nullifier> {
        self.inputs.iter().map(NoteWitness::nullifier).collect()
    }

    pub fn output_commitments(&self) -> Vec<Commitment> {
        self.outputs.iter().map(OutputNoteWitness::commitment).collect()
    }

    pub fn validate_public_inputs(&self, tx: &Transaction) -> Result<(), WitnessValidationError> {
        if self.inputs.len() != tx.inputs.len() {
            return Err(WitnessValidationError::InputCountMismatch {
                witness: self.inputs.len(),
                transaction: tx.inputs.len(),
            });
        }

        for (index, (witness, nullifier)) in self.inputs.iter().zip(&tx.inputs).enumerate() {
            let expected = witness.nullifier();
            if expected != *nullifier {
                return Err(WitnessValidationError::InputNullifierMismatch {
                    index,
                    expected,
                    actual: *nullifier,
                });
            }
        }

        Ok(())
    }

    pub fn validate_public_outputs(&self, tx: &Transaction) -> Result<(), WitnessValidationError> {
        if self.outputs.len() != tx.outputs.len() {
            return Err(WitnessValidationError::OutputCountMismatch {
                witness: self.outputs.len(),
                transaction: tx.outputs.len(),
            });
        }

        for (index, (witness, output)) in self.outputs.iter().zip(&tx.outputs).enumerate() {
            let expected = witness.commitment();
            if expected != output.commitment {
                return Err(WitnessValidationError::OutputCommitmentMismatch {
                    index,
                    expected,
                    actual: output.commitment,
                });
            }
        }

        Ok(())
    }

    pub fn validate_public_fields(&self, tx: &Transaction) -> Result<(), WitnessValidationError> {
        self.validate_public_inputs(tx)?;
        self.validate_public_outputs(tx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessValidationError {
    InputCountMismatch {
        witness: usize,
        transaction: usize,
    },
    OutputCountMismatch {
        witness: usize,
        transaction: usize,
    },
    InputNullifierMismatch {
        index: usize,
        expected: Nullifier,
        actual: Nullifier,
    },
    OutputCommitmentMismatch {
        index: usize,
        expected: Commitment,
        actual: Commitment,
    },
}

impl std::fmt::Display for WitnessValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputCountMismatch { witness, transaction } => write!(
                f,
                "witness input count {witness} does not match transaction input count {transaction}"
            ),
            Self::OutputCountMismatch { witness, transaction } => write!(
                f,
                "witness output count {witness} does not match transaction output count {transaction}"
            ),
            Self::InputNullifierMismatch { index, .. } => {
                write!(f, "input witness nullifier mismatch at index {index}")
            }
            Self::OutputCommitmentMismatch { index, .. } => {
                write!(f, "output witness commitment mismatch at index {index}")
            }
        }
    }
}

impl std::error::Error for WitnessValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutput {
    pub commitment: Commitment,
    pub ephemeral_key: [u8; 32], // Diffie-Hellman ephemeral key for scanning
    pub ciphertext: Vec<u8>,     // Encrypted amount and blinding factor
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<Nullifier>,
    pub outputs: Vec<ShieldedOutput>,
    pub public_amount: Amount,
    #[serde(default)]
    pub fee: Amount,
    #[serde(default)]
    pub note_root: NoteRoot,
    #[serde(default)]
    pub proof_system_version: u16,
    pub proof: Vec<u8>,
}

impl Transaction {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn validate_public_shape(&self) -> Result<(), TransactionValidationError> {
        if self.inputs.len() > MAX_INPUTS {
            return Err(TransactionValidationError::TooManyInputs {
                actual: self.inputs.len(),
                max: MAX_INPUTS,
            });
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(TransactionValidationError::TooManyOutputs {
                actual: self.outputs.len(),
                max: MAX_OUTPUTS,
            });
        }

        let mut seen = std::collections::HashSet::new();
        for nf in &self.inputs {
            if !seen.insert(*nf) {
                return Err(TransactionValidationError::DuplicateNullifier(*nf));
            }
        }

        match self.proof_system_version {
            PROOF_SYSTEM_LEGACY_CONSERVATION | PROOF_SYSTEM_CANONICAL_SHIELDED_V1 => {}
            other => return Err(TransactionValidationError::UnsupportedProofSystemVersion(other)),
        }

        let circuit_amount = if self.is_coinbase() {
            self.public_amount
        } else {
            self.public_amount
                .checked_add(self.fee)
                .ok_or(TransactionValidationError::PublicAmountOutOfRange)?
        };
        if circuit_amount > i64::MAX as u64 {
            return Err(TransactionValidationError::PublicAmountOutOfRange);
        }

        Ok(())
    }

    pub fn canonical_public_fields(&self) -> TransactionPublicFields {
        TransactionPublicFields {
            input_nullifiers: self.inputs.clone(),
            output_commitments: self.outputs.iter().map(|out| out.commitment).collect(),
            encrypted_outputs: self.outputs.clone(),
            public_amount: self.public_amount,
            fee: self.fee,
            note_root: self.note_root,
            proof_system_version: self.proof_system_version,
        }
    }

    /// Returns true if this is a coinbase-style transaction (mint or block reward):
    /// no input nullifiers and a positive public_amount.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty() && self.public_amount > 0
    }

    /// Returns the public_amount as the ZK circuit expects it.
    ///
    /// The `aetheris-zkp` conservation circuit enforces:
    ///   net_value = total_in - total_out - public_amount = 0
    ///
    /// For a coinbase tx, `total_in = 0` and `total_out = public_amount`, so
    /// to satisfy the constraint we must pass `public_amount = -self.public_amount`.
    /// For a regular transfer, `public_amount + fee` is exposed to the circuit
    /// so fees cannot be hidden outside the conservation equation.
    pub fn circuit_public_amount(&self) -> i64 {
        let public_amount = if self.is_coinbase() {
            self.public_amount
        } else {
            self.public_amount.saturating_add(self.fee)
        };
        let public_amount = i64::try_from(public_amount).unwrap_or(i64::MAX);
        if self.is_coinbase() {
            -public_amount
        } else {
            public_amount
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionPublicFields {
    pub input_nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<Commitment>,
    pub encrypted_outputs: Vec<ShieldedOutput>,
    pub public_amount: Amount,
    pub fee: Amount,
    pub note_root: NoteRoot,
    pub proof_system_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionValidationError {
    TooManyInputs { actual: usize, max: usize },
    TooManyOutputs { actual: usize, max: usize },
    DuplicateNullifier(Nullifier),
    UnsupportedProofSystemVersion(u16),
    PublicAmountOutOfRange,
}

impl std::fmt::Display for TransactionValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyInputs { actual, max } => {
                write!(f, "too many transaction inputs: {actual} > {max}")
            }
            Self::TooManyOutputs { actual, max } => {
                write!(f, "too many transaction outputs: {actual} > {max}")
            }
            Self::DuplicateNullifier(_) => write!(f, "duplicate input nullifier"),
            Self::UnsupportedProofSystemVersion(version) => {
                write!(f, "unsupported proof system version: {version}")
            }
            Self::PublicAmountOutOfRange => write!(f, "transaction public amount plus fee is out of range"),
        }
    }
}

impl std::error::Error for TransactionValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub timestamp: u64,
    pub vdf_result: Vec<u8>,  // Mathematical result of VDF
    pub vdf_proof: Vec<u8>,   // Wesolowski or ZK proof of VDF
    pub height: u64,
    pub difficulty: u64,      // Current VDF difficulty
    pub recursive_proof: Vec<u8>, // Halo2 recursive SNARK (empty = trusted fallback)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub amount: Amount,
    pub owner_pubkey: [u8; 32],
    pub asset_id: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    SyncRequest { start_height: u64, end_height: u64 },
    SyncResponse { blocks: Vec<Block> },
    Transaction(Transaction),
}

pub const ATOMS_PER_AET: u64 = 100_000_000;

/// Total blocks over which the block reward linearly decreases to zero.
/// 42,000,000 blocks ≈ 13.3 years at 10 seconds/block.
/// Total supply = INITIAL_BLOCK_REWARD_ATOMS * EMISSION_BLOCKS / 2 ≈ 21,000,000 AET.
pub const EMISSION_BLOCKS: u64 = 42_000_000;

/// Initial block reward at height 0: 1 AET (100,000,000 atoms).
pub const INITIAL_BLOCK_REWARD_ATOMS: u64 = ATOMS_PER_AET;

/// Linear emission: reward decreases from 1 AET at height 0 to 0 at EMISSION_BLOCKS.
pub fn calculate_block_reward_atoms(height: u64) -> u64 {
    if height >= EMISSION_BLOCKS {
        return 0;
    }
    let remaining = EMISSION_BLOCKS - height;
    ((remaining as u128) * (INITIAL_BLOCK_REWARD_ATOMS as u128) / (EMISSION_BLOCKS as u128)) as u64
}

/// C-4: Deterministic genesis identity hash — excludes proof bytes and
/// randomness-dependent fields (ephemeral_key, ciphertext nonce). Only
/// hashes the immutable economic parameters: amounts, commitments, and
/// timestamp. Stable across runs and machines for the same config.
pub fn genesis_identity_hash(block: &Block) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AETHERIS_GENESIS_V1");
    hasher.update(&block.header.parent_hash);
    hasher.update(&block.header.timestamp.to_le_bytes());
    for tx in &block.transactions {
        hasher.update(&tx.public_amount.to_le_bytes());
        for out in &tx.outputs {
            hasher.update(&out.commitment);
        }
    }
    hasher.finalize().into()
}

pub fn block_hash(block: &Block) -> Hash {
    let encoded = bincode::serialize(block).unwrap();
    blake3::hash(&encoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_header(height: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: [0u8; 32],
            state_root: [1u8; 32],
            timestamp: 1000 + height,
            vdf_result: vec![0xAA; 32],
            vdf_proof: vec![0xBB; 32],
            height,
            difficulty: VDF_DIFFICULTY,
            recursive_proof: vec![],
        }
    }

    fn dummy_output(seed: u8) -> ShieldedOutput {
        ShieldedOutput {
            commitment: [seed; 32],
            ephemeral_key: [seed ^ 0xFF; 32],
            ciphertext: vec![seed; 64],
        }
    }

    fn dummy_tx(seed: u8) -> Transaction {
        Transaction {
            inputs: vec![[seed; 32]],
            outputs: vec![dummy_output(seed), dummy_output(seed + 1)],
            public_amount: (seed as Amount) * 100,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_LEGACY_CONSERVATION,
            proof: vec![seed; 128],
        }
    }

    fn dummy_block(height: u64, num_txs: usize) -> Block {
        Block {
            header: dummy_header(height),
            transactions: (0..num_txs).map(|i| dummy_tx(i as u8)).collect(),
        }
    }

    #[test]
    fn test_constants_correctness() {
        assert_eq!(VDF_DIFFICULTY, 1_600_000);
        assert_eq!(TARGET_BLOCK_TIME, 10);
        assert_eq!(DIFFICULTY_ADJUSTMENT_INTERVAL, 10);
        assert_eq!(MAX_VDF_SPEED, 5_000_000);
    }

    #[test]
    fn test_block_serialization_roundtrip() {
        let block = dummy_block(42, 3);
        let encoded = bincode::serialize(&block).unwrap();
        let decoded: Block = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.header.height, 42);
        assert_eq!(decoded.transactions.len(), 3);
        assert_eq!(decoded.header.vdf_result, block.header.vdf_result);
        assert_eq!(decoded.header.parent_hash, [0u8; 32]);
    }

    #[test]
    fn test_block_header_fields() {
        let h = dummy_header(7);
        assert_eq!(h.parent_hash, [0u8; 32]);
        assert_eq!(h.state_root, [1u8; 32]);
        assert_eq!(h.timestamp, 1007);
        assert_eq!(h.height, 7);
        assert_eq!(h.difficulty, VDF_DIFFICULTY);
    }

    #[test]
    fn test_transaction_construction() {
        let tx = dummy_tx(5);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.public_amount, 500);
        assert_eq!(tx.proof.len(), 128);
        assert_eq!(tx.inputs[0], [5u8; 32]);
    }

    #[test]
    fn test_shielded_output_layout() {
        let out = dummy_output(9);
        assert_eq!(out.commitment.len(), 32);
        assert_eq!(out.ephemeral_key.len(), 32);
        assert_eq!(out.ciphertext.len(), 64);
        let serialized = bincode::serialize(&out).unwrap();
        assert!(serialized.len() >= 1 + 32 + 32 + 64);
    }

    #[test]
    fn test_empty_block_hash_differs_from_non_empty() {
        let empty = dummy_block(0, 0);
        let non_empty = dummy_block(0, 1);
        let h_empty = block_hash(&empty);
        let h_non_empty = block_hash(&non_empty);
        assert_ne!(h_empty, h_non_empty);
    }

    #[test]
    fn test_block_hash_consistency() {
        let block = dummy_block(1, 2);
        let h1 = block_hash(&block);
        let h2 = block_hash(&block);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_heights_different_hashes() {
        let b1 = dummy_block(1, 1);
        let b2 = dummy_block(2, 1);
        assert_ne!(block_hash(&b1), block_hash(&b2));
    }

    #[test]
    fn test_tx_order_affects_hash() {
        let mut block = dummy_block(0, 2);
        let h_original = block_hash(&block);
        block.transactions.swap(0, 1);
        let h_swapped = block_hash(&block);
        assert_ne!(h_original, h_swapped);
    }

    #[test]
    fn test_multiple_transaction_block() {
        let block = dummy_block(5, 5);
        assert_eq!(block.transactions.len(), 5);
        let encoded = bincode::serialize(&block).unwrap();
        let decoded: Block = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.transactions.len(), 5);
        for (i, tx) in decoded.transactions.iter().enumerate() {
            assert_eq!(tx.public_amount, (i as u64) * 100);
        }
    }

    #[test]
    fn test_zero_transaction_block() {
        let block = dummy_block(10, 0);
        assert!(block.transactions.is_empty());
        let encoded = bincode::serialize(&block).unwrap();
        let decoded: Block = bincode::deserialize(&encoded).unwrap();
        assert!(decoded.transactions.is_empty());
    }

    #[test]
    fn test_record_fields() {
        let rec = Record {
            amount: 1000,
            owner_pubkey: [0xAB; 32],
            asset_id: [0xCD; 32],
            nonce: [0xEF; 32],
        };
        assert_eq!(rec.amount, 1000);
        assert_eq!(rec.owner_pubkey[0], 0xAB);
        let encoded = bincode::serialize(&rec).unwrap();
        let decoded: Record = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.amount, 1000);
    }


    #[test]
    fn test_note_plaintext_serialization_roundtrip() {
        let note = NotePlaintext {
            amount: 42,
            asset_id: AET_ASSET_ID,
            owner: [0x11; 32],
            rho: [0x22; 32],
            rseed: [0x33; 32],
            memo: b"canonical memo".to_vec(),
        };
        let encoded = serde_json::to_vec(&note).unwrap();
        let decoded: NotePlaintext = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, note);
    }

    #[test]
    fn test_canonical_note_commitment_binds_plaintext_fields() {
        let note = NotePlaintext {
            amount: 42,
            asset_id: AET_ASSET_ID,
            owner: [0x11; 32],
            rho: [0x22; 32],
            rseed: [0x33; 32],
            memo: b"canonical memo".to_vec(),
        };
        let blinding = [0x44; 32];
        let commitment = note.commitment(&blinding);

        assert_eq!(commitment, canonical_note_commitment(&note, &blinding));

        let mut changed_amount = note.clone();
        changed_amount.amount += 1;
        assert_ne!(commitment, changed_amount.commitment(&blinding));

        let mut changed_asset = note.clone();
        changed_asset.asset_id = [0x55; 32];
        assert_ne!(commitment, changed_asset.commitment(&blinding));

        let mut changed_owner = note.clone();
        changed_owner.owner = [0x66; 32];
        assert_ne!(commitment, changed_owner.commitment(&blinding));

        let mut changed_rho = note.clone();
        changed_rho.rho = [0x77; 32];
        assert_ne!(commitment, changed_rho.commitment(&blinding));

        let mut changed_rseed = note.clone();
        changed_rseed.rseed = [0x88; 32];
        assert_ne!(commitment, changed_rseed.commitment(&blinding));

        let mut changed_memo = note.clone();
        changed_memo.memo.push(b'!');
        assert_ne!(commitment, changed_memo.commitment(&blinding));

        assert_ne!(commitment, note.commitment(&[0x99; 32]));
    }

    #[test]
    fn test_note_witness_nullifier_binds_note_key_and_position() {
        let witness = NoteWitness {
            note: NotePlaintext {
                amount: 42,
                asset_id: AET_ASSET_ID,
                owner: [0x11; 32],
                rho: [0x22; 32],
                rseed: [0x33; 32],
                memo: b"canonical memo".to_vec(),
            },
            blinding: [0x44; 32],
            nullifier_key: [0x55; 32],
            merkle_path: vec![[0x66; 32]],
            merkle_position: 7,
        };
        let nullifier = witness.nullifier();
        assert_eq!(
            nullifier,
            canonical_nullifier(&witness.commitment(), &witness.nullifier_key, 7)
        );

        let mut changed_key = witness.clone();
        changed_key.nullifier_key = [0x77; 32];
        assert_ne!(nullifier, changed_key.nullifier());

        let mut changed_position = witness.clone();
        changed_position.merkle_position = 8;
        assert_ne!(nullifier, changed_position.nullifier());

        let mut changed_note = witness.clone();
        changed_note.note.rho = [0x88; 32];
        assert_ne!(nullifier, changed_note.nullifier());
    }

    #[test]
    fn test_transaction_witness_validates_input_nullifiers() {
        let input_witness = NoteWitness {
            note: NotePlaintext {
                amount: 42,
                asset_id: AET_ASSET_ID,
                owner: [0x11; 32],
                rho: [0x22; 32],
                rseed: [0x33; 32],
                memo: b"canonical memo".to_vec(),
            },
            blinding: [0x44; 32],
            nullifier_key: [0x55; 32],
            merkle_path: vec![[0x66; 32]],
            merkle_position: 7,
        };
        let mut tx = dummy_tx(1);
        tx.inputs = vec![input_witness.nullifier()];
        tx.outputs.clear();
        let witness = TransactionWitness {
            inputs: vec![input_witness.clone()],
            outputs: vec![],
        };

        assert_eq!(witness.input_nullifiers(), tx.inputs);
        assert!(witness.validate_public_inputs(&tx).is_ok());
        assert!(witness.validate_public_fields(&tx).is_ok());

        let mut changed_witness = witness.clone();
        changed_witness.inputs[0].nullifier_key = [0x77; 32];
        assert!(matches!(
            changed_witness.validate_public_inputs(&tx),
            Err(WitnessValidationError::InputNullifierMismatch { index: 0, .. })
        ));

        let mut missing_input_tx = tx.clone();
        missing_input_tx.inputs.clear();
        assert!(matches!(
            witness.validate_public_inputs(&missing_input_tx),
            Err(WitnessValidationError::InputCountMismatch { witness: 1, transaction: 0 })
        ));
    }

    #[test]
    fn test_transaction_witness_validates_output_commitments() {
        let output_witness = OutputNoteWitness {
            note: NotePlaintext {
                amount: 42,
                asset_id: AET_ASSET_ID,
                owner: [0x11; 32],
                rho: [0x22; 32],
                rseed: [0x33; 32],
                memo: b"canonical memo".to_vec(),
            },
            blinding: [0x44; 32],
        };
        let mut tx = dummy_tx(1);
        tx.outputs = vec![ShieldedOutput {
            commitment: output_witness.commitment(),
            ephemeral_key: [0x55; 32],
            ciphertext: b"encrypted".to_vec(),
        }];
        let witness = TransactionWitness {
            inputs: vec![],
            outputs: vec![output_witness.clone()],
        };

        assert_eq!(witness.output_commitments(), vec![tx.outputs[0].commitment]);
        assert!(witness.validate_public_outputs(&tx).is_ok());

        let mut changed_witness = witness.clone();
        changed_witness.outputs[0].note.owner = [0x66; 32];
        assert!(matches!(
            changed_witness.validate_public_outputs(&tx),
            Err(WitnessValidationError::OutputCommitmentMismatch { index: 0, .. })
        ));

        let mut missing_output_tx = tx.clone();
        missing_output_tx.outputs.clear();
        assert!(matches!(
            witness.validate_public_outputs(&missing_output_tx),
            Err(WitnessValidationError::OutputCountMismatch { witness: 1, transaction: 0 })
        ));
    }

    #[test]
    fn test_transaction_public_fields_project_consensus_data() {
        let mut tx = dummy_tx(7);
        tx.fee = 3;
        tx.note_root = [0x44; 32];
        tx.proof_system_version = PROOF_SYSTEM_CANONICAL_SHIELDED_V1;

        let public = tx.canonical_public_fields();
        assert_eq!(public.input_nullifiers, tx.inputs);
        assert_eq!(public.output_commitments, vec![[7u8; 32], [8u8; 32]]);
        assert_eq!(public.encrypted_outputs, tx.outputs);
        assert_eq!(public.public_amount, 700);
        assert_eq!(public.fee, 3);
        assert_eq!(public.note_root, [0x44; 32]);
        assert_eq!(public.proof_system_version, PROOF_SYSTEM_CANONICAL_SHIELDED_V1);
    }

    #[test]
    fn test_transaction_json_defaults_legacy_fields() {
        let legacy_json = r#"{
            "inputs": [],
            "outputs": [],
            "public_amount": 0,
            "proof": []
        }"#;
        let tx: Transaction = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(tx.fee, 0);
        assert_eq!(tx.note_root, [0u8; 32]);
        assert_eq!(tx.proof_system_version, PROOF_SYSTEM_LEGACY_CONSERVATION);
    }

    #[test]
    fn test_transaction_bytes_roundtrip() {
        let tx = dummy_tx(3);
        let encoded = tx.to_bytes().unwrap();
        let decoded = Transaction::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.inputs, tx.inputs);
        assert_eq!(decoded.canonical_public_fields(), tx.canonical_public_fields());
        assert_eq!(decoded.proof, tx.proof);
    }

    #[test]
    fn test_transaction_public_shape_rejects_too_many_inputs() {
        let mut tx = dummy_tx(1);
        tx.inputs = vec![[1u8; 32]; MAX_INPUTS + 1];
        assert!(matches!(
            tx.validate_public_shape(),
            Err(TransactionValidationError::TooManyInputs { actual, max })
                if actual == MAX_INPUTS + 1 && max == MAX_INPUTS
        ));
    }

    #[test]
    fn test_transaction_public_shape_rejects_duplicate_nullifier() {
        let mut tx = dummy_tx(1);
        tx.inputs = vec![[9u8; 32], [9u8; 32]];
        assert_eq!(
            tx.validate_public_shape(),
            Err(TransactionValidationError::DuplicateNullifier([9u8; 32]))
        );
    }

    #[test]
    fn test_transaction_public_shape_rejects_unknown_proof_version() {
        let mut tx = dummy_tx(1);
        tx.proof_system_version = 99;
        assert_eq!(
            tx.validate_public_shape(),
            Err(TransactionValidationError::UnsupportedProofSystemVersion(99))
        );
    }

    #[test]
    fn test_p2p_message_sync_request() {
        let msg = P2PMessage::SyncRequest { start_height: 0, end_height: 100 };
        let encoded = bincode::serialize(&msg).unwrap();
        let decoded: P2PMessage = bincode::deserialize(&encoded).unwrap();
        match decoded {
            P2PMessage::SyncRequest { start_height, end_height } => {
                assert_eq!(start_height, 0);
                assert_eq!(end_height, 100);
            }
            _ => panic!("Wrong variant"),
        }
    }

    fn mk_tx(inputs: Vec<[u8; 32]>, public_amount: u64) -> Transaction {
        Transaction {
            inputs,
            outputs: vec![],
            public_amount,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_LEGACY_CONSERVATION,
            proof: vec![],
        }
    }

    #[test]
    fn test_is_coinbase_mint() {
        assert!(mk_tx(vec![], 1000).is_coinbase());
    }

    #[test]
    fn test_is_coinbase_block_reward() {
        assert!(mk_tx(vec![], 50 * 100_000_000).is_coinbase());
    }

    #[test]
    fn test_is_not_coinbase_transfer() {
        assert!(!mk_tx(vec![[0u8; 32]], 0).is_coinbase());
    }

    #[test]
    fn test_is_not_coinbase_topup_with_inputs() {
        assert!(!mk_tx(vec![[0u8; 32]], 1000).is_coinbase());
    }

    #[test]
    fn test_circuit_public_amount_negates_coinbase() {
        assert_eq!(mk_tx(vec![], 1000).circuit_public_amount(), -1000);
    }

    #[test]
    fn test_circuit_public_amount_preserves_transfer() {
        assert_eq!(mk_tx(vec![[0u8; 32]], 0).circuit_public_amount(), 0);
    }

    #[test]
    fn test_circuit_public_amount_preserves_topup() {
        assert_eq!(mk_tx(vec![[0u8; 32]], 1000).circuit_public_amount(), 1000);
    }


    #[test]
    fn test_circuit_public_amount_includes_transfer_fee() {
        let mut tx = mk_tx(vec![[0u8; 32]], 7);
        tx.fee = 3;
        assert_eq!(tx.circuit_public_amount(), 10);
    }

    #[test]
    fn test_validate_public_shape_rejects_public_amount_fee_overflow() {
        let mut tx = mk_tx(vec![[0u8; 32]], u64::MAX);
        tx.fee = 1;
        assert_eq!(
            tx.validate_public_shape(),
            Err(TransactionValidationError::PublicAmountOutOfRange)
        );
    }

    /// Edge case: empty inputs + public_amount = 0 is a true no-op.
    /// is_coinbase() must be false (no value is being created), so circuit_public_amount()
    /// returns 0. The ZK circuit net_value = 0 - 0 - 0 = 0 trivially holds.
    #[test]
    fn test_noop_tx_is_not_coinbase() {
        let tx = mk_tx(vec![], 0);
        assert!(!tx.is_coinbase());
        assert_eq!(tx.circuit_public_amount(), 0);
    }

    #[test]
    fn test_linear_emission_initial_reward() {
        assert_eq!(calculate_block_reward_atoms(0), INITIAL_BLOCK_REWARD_ATOMS);
    }

    #[test]
    fn test_linear_emission_midpoint() {
        let mid = EMISSION_BLOCKS / 2;
        assert_eq!(calculate_block_reward_atoms(mid), INITIAL_BLOCK_REWARD_ATOMS / 2);
    }

    #[test]
    fn test_linear_emission_end() {
        assert_eq!(calculate_block_reward_atoms(EMISSION_BLOCKS), 0);
        assert_eq!(calculate_block_reward_atoms(EMISSION_BLOCKS + 1), 0);
    }

    #[test]
    fn test_linear_emission_monotonic() {
        for h in (0..EMISSION_BLOCKS).step_by(1_000_000) {
            assert!(calculate_block_reward_atoms(h) >= calculate_block_reward_atoms(h + 1));
        }
    }
}
