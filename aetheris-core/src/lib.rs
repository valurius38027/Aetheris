use serde::{Deserialize, Serialize};

pub type Amount = u64;
pub type Hash = [u8; 32];
pub type Nullifier = Hash;
pub type Commitment = Hash;

pub const VDF_DIFFICULTY: u64 = 1_600_000;
pub const TARGET_BLOCK_TIME: u64 = 10; // Target 10 seconds per block
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 10; // Adjust difficulty every 10 blocks
pub const MAX_VDF_SPEED: u64 = 5_000_000; // Max 5M iterations/sec (Anti-acceleration threshold)
pub const MAX_INPUTS: usize = 5;
pub const MAX_OUTPUTS: usize = 5;
pub const EXPECTED_GENESIS_HASH: &str = "15db1dd5d89d5d1e19ee65a2221e156ea84083f59a127b99a595fe6e305b914c";

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub proof: Vec<u8>,
}

impl Transaction {
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
    /// For a regular transfer, `public_amount` is unchanged.
    pub fn circuit_public_amount(&self) -> i64 {
        if self.is_coinbase() {
            -(self.public_amount as i64)
        } else {
            self.public_amount as i64
        }
    }
}

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
    pub aggregate_proof: Vec<u8>, // Recursive SNARK aggregating all TX proofs
    pub height: u64,
    pub difficulty: u64,      // Current VDF difficulty
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

pub fn calculate_block_reward_atoms(height: u64) -> u64 {
    let initial_reward = 50 * ATOMS_PER_AET;
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    initial_reward >> halvings
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
            aggregate_proof: vec![0xCC; 64],
            height,
            difficulty: VDF_DIFFICULTY,
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

    /// Edge case: empty inputs + public_amount = 0 is a true no-op.
    /// is_coinbase() must be false (no value is being created), so circuit_public_amount()
    /// returns 0. The ZK circuit net_value = 0 - 0 - 0 = 0 trivially holds.
    #[test]
    fn test_noop_tx_is_not_coinbase() {
        let tx = mk_tx(vec![], 0);
        assert!(!tx.is_coinbase());
        assert_eq!(tx.circuit_public_amount(), 0);
    }
}
