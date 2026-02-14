use aetheris_core::{Block, ShieldedOutput};
use std::collections::{HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use sled::Db;

pub struct LedgerState {
    pub nullifiers: HashSet<[u8; 32]>,
    pub commitments: HashSet<[u8; 32]>,
    pub all_outputs: Vec<ShieldedOutput>,
    pub db: Db,
    pub height: u64,
    pub last_block_hash: [u8; 32],
    pub last_aggregate_proof: Vec<u8>,
}

impl LedgerState {
    pub fn new(db_path: &str) -> Self {
        let db = sled::open(db_path).expect("Failed to open database");
        Self::new_with_db(db)
    }

    pub fn new_with_db(db: Db) -> Self {
        let mut state = Self {
            nullifiers: HashSet::new(),
            commitments: HashSet::new(),
            all_outputs: Vec::new(),
            db,
            height: 0,
            last_block_hash: [0u8; 32],
            last_aggregate_proof: b"genesis_proof".to_vec(),
        };
        state.restore_from_db();
        state
    }

    pub fn restore_from_db(&mut self) {
        // Restore height
        if let Ok(Some(h_bytes)) = self.db.get(b"height") {
            if h_bytes.len() == 8 {
                self.height = u64::from_le_bytes(h_bytes.as_ref().try_into().unwrap());
            } else {
                let h_str = String::from_utf8_lossy(&h_bytes);
                self.height = h_str.parse().unwrap_or(0);
            }
        }

        // Restore last_block_hash from DB if it exists
        if let Ok(Some(hash_bytes)) = self.db.get(b"last_block_hash") {
            if hash_bytes.len() == 32 {
                self.last_block_hash.copy_from_slice(&hash_bytes);
            }
        }
        
        // Restore nullifiers and commitments
        for i in 0..self.height {
            if let Ok(Some(block_bytes)) = self.db.get(format!("block_{}", i).as_bytes()) {
                if let Ok(block) = bincode::deserialize::<Block>(&block_bytes) {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&block_bytes);
                    self.last_block_hash = hasher.finalize().into();
                    self.last_aggregate_proof = block.header.aggregate_proof.clone();

                    for tx in &block.transactions {
                        for nf in &tx.inputs { self.nullifiers.insert(*nf); }
                        for out in &tx.outputs { 
                            self.commitments.insert(out.commitment);
                            self.all_outputs.push(out.clone());
                        }
                    }
                }
            }
        }
    }

    pub fn rollback_block(&mut self) -> Result<(), String> {
        if self.height == 0 {
            return Err("Cannot rollback genesis block".into());
        }

        let target_height = self.height - 1;
        if let Ok(Some(block_bytes)) = self.db.get(format!("block_{}", target_height).as_bytes()) {
            let block = bincode::deserialize::<Block>(&block_bytes).map_err(|e| e.to_string())?;

            // Remove nullifiers and commitments
            for tx in &block.transactions {
                for nf in &tx.inputs {
                    self.nullifiers.remove(nf);
                }
                for out in &tx.outputs {
                    self.commitments.remove(&out.commitment);
                    // Remove from all_outputs (inefficient in prototype, but correct)
                    self.all_outputs.retain(|o| o.commitment != out.commitment);
                }
            }

            // Delete block from DB
            self.db.remove(format!("block_{}", target_height).as_bytes()).map_err(|e| e.to_string())?;

            // Update height
            self.height = target_height;
            self.db.insert(b"height", &self.height.to_le_bytes()).map_err(|e| e.to_string())?;

            // Update last_block_hash and last_aggregate_proof
            if self.height > 0 {
                let prev_height = self.height - 1;
                if let Ok(Some(prev_block_bytes)) = self.db.get(format!("block_{}", prev_height).as_bytes()) {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&prev_block_bytes);
                    self.last_block_hash = hasher.finalize().into();
                    let prev_block = bincode::deserialize::<Block>(&prev_block_bytes).map_err(|e| e.to_string())?;
                    self.last_aggregate_proof = prev_block.header.aggregate_proof;
                }
            } else {
                self.last_block_hash = [0u8; 32];
                self.last_aggregate_proof = b"genesis_proof".to_vec();
            }

            self.db.insert(b"last_block_hash", &self.last_block_hash).map_err(|e| e.to_string())?;
            self.db.flush().map_err(|e| e.to_string())?;

            Ok(())
        } else {
            Err(format!("Block #{} not found in DB for rollback", target_height))
        }
    }

    pub fn get_block(&self, height: u64) -> Option<Block> {
        if let Ok(Some(data)) = self.db.get(format!("block_{}", height).as_bytes()) {
            bincode::deserialize::<Block>(&data).ok()
        } else {
            None
        }
    }

    pub fn get_state_root(&self) -> [u8; 32] {
        // In a real system, this would be a Merkle/JMT root.
        // For the prototype, we use the last block hash as a state commitment proxy.
        self.last_block_hash
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), String> {
        self.apply_block_with_validation(block, true)
    }

    pub fn apply_block_with_validation(&mut self, block: Block, validate_parent: bool) -> Result<(), String> {
        // 0. Genesis Hash Validation (Network Identity)
        if block.header.height == 0 {
            let data = bincode::serialize(&block).map_err(|e| e.to_string())?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(&data);
            let current_hash = hex::encode(hasher.finalize().as_bytes());
            
            // This is the hardcoded "Network ID"
            const EXPECTED_GENESIS_HASH: &str = "78096181f215049a421f660f5454641579a32c636e0d9a695e2637a77519199c";
            
            if current_hash != EXPECTED_GENESIS_HASH {
                return Err(format!("CRITICAL: Genesis block hash mismatch! Found: {}", current_hash));
            }
        }

        // 1. Validate Height
        if block.header.height != self.height {
            return Err(format!("Invalid block height: expected {}, got {}", self.height, block.header.height));
        }

        // 2. Validate Parent Hash and Timestamp (except for genesis)
        if self.height > 0 {
            if let Some(prev_block_bytes) = self.db.get(format!("block_{}", self.height - 1).as_bytes()).ok().flatten() {
                let prev_block = bincode::deserialize::<Block>(&prev_block_bytes).map_err(|e| e.to_string())?;
                
                // Validate Parent Hash
                if validate_parent && block.header.parent_hash != self.last_block_hash {
                    return Err("Parent hash mismatch - potential fork detected".into());
                }

                // Scheme 4: Timestamp Validation (Anti-VDF Acceleration Attack)
                // Rule A: Timestamp must be strictly monotonic
                if block.header.timestamp <= prev_block.header.timestamp {
                    return Err(format!("Block timestamp too old: {} <= {}", block.header.timestamp, prev_block.header.timestamp));
                }

                // Rule B: Future drift protection (Max 15 seconds)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if block.header.timestamp > now + 15 {
                    return Err(format!("Block timestamp too far in future: {} > {}", block.header.timestamp, now + 15));
                }

                // Rule C: Calculation Variance Check (Dynamic VDF Estimation)
                // We calculate the minimum possible time required based on the block's difficulty
                // and a maximum "theoretically possible" VDF speed.
                let min_required_time = block.header.difficulty / aetheris_core::MAX_VDF_SPEED;
                let elapsed = block.header.timestamp.saturating_sub(prev_block.header.timestamp);
                
                if elapsed < min_required_time {
                    return Err(format!(
                        "Block generated impossibly fast: elapsed {}s, min required {}s (Difficulty: {})", 
                        elapsed, min_required_time, block.header.difficulty
                    ));
                }
            }
        }

        // 3. Full validation: VDF and ZK Proof
        // Verify VDF
        if self.height > 0 {
            let vdf = aetheris_crypto::VDF::new(block.header.difficulty);
            if !vdf.verify(&self.last_block_hash, &block.header.vdf_result, &block.header.vdf_proof) {
                return Err(format!("VDF verification failed for block #{}", block.header.height));
            }
        }

        // Verify Aggregate ZK Proof
        let public_amounts: Vec<i64> = block.transactions.iter().map(|tx| tx.public_amount as i64).collect();
        let tx_proofs: Vec<Vec<u8>> = block.transactions.iter().map(|tx| tx.proof.clone()).collect();
        if !aetheris_zkp::ZKProofSystem::verify_aggregate(
            &block.header.aggregate_proof,
            &self.last_aggregate_proof,
            &tx_proofs,
            &public_amounts,
            block.header.height,
            &block.header.state_root
        ) {
            return Err(format!("Aggregate ZK Proof verification failed for block #{}", block.header.height));
        }

        // 4. Update State (Nullifiers & Commitments)
        for tx in &block.transactions {
            for nf in &tx.inputs {
                self.nullifiers.insert(*nf);
            }
            for out in &tx.outputs {
                self.commitments.insert(out.commitment);
                self.all_outputs.push(out.clone());
            }
        }

        let data = bincode::serialize(&block).map_err(|e| e.to_string())?;

        // 6. Update Metadata
        let mut hasher = blake3::Hasher::new();
        hasher.update(&data);
        self.last_block_hash = hasher.finalize().into();
        self.last_aggregate_proof = block.header.aggregate_proof.clone();
        self.height += 1;

        // 5. Persist Block
        self.db.insert(format!("block_{}", self.height - 1).as_bytes(), data).map_err(|e| e.to_string())?;

        // 7. Persist Metadata
        self.db.insert(b"height", &self.height.to_le_bytes()).map_err(|e| e.to_string())?;
        self.db.insert(b"last_block_hash", &self.last_block_hash).map_err(|e| e.to_string())?;
        self.db.flush().map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Reorganize the chain to a new set of blocks, rolling back if necessary.
    pub fn reorganize(&mut self, new_blocks: Vec<Block>) -> Result<(), String> {
        if new_blocks.is_empty() {
            return Ok(());
        }

        let first_new_height = new_blocks[0].header.height;
        
        // 1. Rollback to the common ancestor
        while self.height > first_new_height {
            println!("[Ledger] Rolling back block #{} for reorganization", self.height - 1);
            self.rollback_block()?;
        }

        // 2. Apply the new blocks
        for block in new_blocks {
            println!("[Ledger] Applying new block #{} during reorganization", block.header.height);
            self.apply_block(block)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aetheris_core::{BlockHeader};

    #[test]
    fn test_vdf_dynamic_time_validation() {
        let db_path = "test_vdf_validation_db";
        let _ = std::fs::remove_dir_all(db_path);
        let mut state = LedgerState::new(db_path);
        
        // Manually set up state to skip height 0 hash validation in apply_block
        state.height = 1;
        state.last_block_hash = [1u8; 32];
        let prev_timestamp = 1000;
        
        // Mock block #0 in DB
        let prev_block = Block {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: prev_timestamp,
                vdf_result: vec![],
                vdf_proof: vec![],
                aggregate_proof: vec![],
                height: 0,
                difficulty: 100,
            },
            transactions: vec![],
        };
        state.db.insert(b"block_0", bincode::serialize(&prev_block).unwrap()).unwrap();

        // Case 1: Block too fast for difficulty
        // Difficulty 10M, MAX_SPEED 5M -> Needs at least 2 seconds
        let fast_block = Block {
            header: BlockHeader {
                parent_hash: state.last_block_hash,
                state_root: [0u8; 32],
                timestamp: 1001, // Only 1s elapsed since block 0
                vdf_result: vec![],
                vdf_proof: vec![],
                aggregate_proof: vec![],
                height: 1,
                difficulty: 10_000_000, 
            },
            transactions: vec![],
        };
        
        let result = state.apply_block_with_validation(fast_block.clone(), true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Block generated impossibly fast"));

        // Case 2: Block timing is valid
        let mut valid_block = fast_block.clone();
        valid_block.header.timestamp = 1003; // 3s elapsed (>= 2s)
        
        let result = state.apply_block_with_validation(valid_block, true);
        // It should pass Rule C and move to Rule D (VDF Verification), which will fail due to empty proofs
        if let Err(e) = result {
            assert!(!e.contains("Block generated impossibly fast"));
        }

        let _ = std::fs::remove_dir_all(db_path);
    }
}
