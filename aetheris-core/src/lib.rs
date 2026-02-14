use serde::{Deserialize, Serialize};

pub type Amount = u64;
pub type Hash = [u8; 32];
pub type Nullifier = Hash;
pub type Commitment = Hash;

pub const VDF_DIFFICULTY: u64 = 1_600_000;
pub const TARGET_BLOCK_TIME: u64 = 10; // Target 10 seconds per block
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 10; // Adjust difficulty every 10 blocks
pub const MAX_VDF_SPEED: u64 = 5_000_000; // Max 5M iterations/sec (Anti-acceleration threshold)

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
