use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use aetheris_core::{Hash, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    pub height: u64,
    pub block_hash: Hash,
    pub transactions: Vec<Transaction>,
    pub vdf_result: Vec<u8>,
    pub vdf_proof: Vec<u8>,
    pub aggregate_proof: Vec<u8>,
    pub sender: String, // PeerId string
    pub difficulty: u64,
    pub state_root: Hash,
    pub timestamp: u64,
}

/// Aetheris Mathematical Arbitrator
/// Instead of multi-round voting, Aetheris nodes independently converge
/// on the "mathematically correct" winner for each height.
pub struct MathematicalArbitrator {
    pub height: u64,
    pub proposals: HashMap<u64, Vec<BlockProposal>>,
    pub prev_block_hash: Hash, // New field for entropy
}

impl MathematicalArbitrator {
    pub fn new() -> Self {
        Self {
            height: 0,
            proposals: HashMap::new(),
            prev_block_hash: [0u8; 32],
        }
    }

    /// Sets the previous block hash to update entropy for the next arbitration
    pub fn set_prev_hash(&mut self, hash: Hash) {
        self.prev_block_hash = hash;
    }

    /// Adds a proposal and returns the current best one for the given height.
    pub fn add_proposal(&mut self, proposal: BlockProposal) -> Option<BlockProposal> {
        if proposal.height < self.height {
            return None;
        }

        let proposals = self.proposals.entry(proposal.height).or_insert_with(Vec::new);
        
        // Check if we already have this proposal from the same sender
        if !proposals.iter().any(|p| p.sender == proposal.sender && p.block_hash == proposal.block_hash) {
            proposals.push(proposal.clone());
        }

        self.get_winner(proposal.height)
    }

    /// The core of Aetheris's Mathematical Arbitration:
    /// Ranks proposals by the full serialized block hash (blake3 of serialized Block).
    /// This binds entropy to the entire block content (transactions, state_root, VDF result, timestamp),
    /// preventing grinding attacks on a subset of fields.
    pub fn get_winner(&self, height: u64) -> Option<BlockProposal> {
        self.proposals.get(&height)?.iter().min_by_key(|p| {
            p.block_hash
        }).cloned()
    }

    pub fn advance_height(&mut self) {
        self.proposals.remove(&self.height);
        self.height += 1;
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        // Clean up old proposals
        self.proposals.retain(|&h, _| h >= height);
    }

    /// Calculates the difficulty for the next block based on the previous blocks' timestamps.
    /// This is a simple retargeting algorithm similar to Bitcoin but for VDF difficulty.
    pub fn calculate_next_difficulty(&self, last_block: &aetheris_core::Block, prev_adjustment_block: &aetheris_core::Block) -> u64 {
        if last_block.header.height % aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return last_block.header.difficulty;
        }

        let actual_time = last_block.header.timestamp.saturating_sub(prev_adjustment_block.header.timestamp);
        let target_time = aetheris_core::TARGET_BLOCK_TIME * aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL;

        // Dampen the adjustment to prevent extreme fluctuations (max 4x or min 0.25x)
        let actual_time = actual_time.clamp(target_time / 4, target_time * 4);
        
        let new_difficulty = (last_block.header.difficulty as u128 * target_time as u128 / actual_time.max(1) as u128) as u64;
        
        println!("[Consensus] Difficulty Adjustment: ActualTime={}s, TargetTime={}s, OldDiff={}, NewDiff={}", 
            actual_time, target_time, last_block.header.difficulty, new_difficulty);
            
        new_difficulty
    }
}
