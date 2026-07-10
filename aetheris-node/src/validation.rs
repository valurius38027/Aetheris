use aetheris_core::{
    genesis_identity_hash, Block, Commitment, Nullifier, Transaction, EXPECTED_GENESIS_HASH,
    VDF_DIFFICULTY,
};
use std::collections::HashSet;

pub fn validate_genesis_block(block: &Block) -> Result<(), String> {
    if block.header.height != 0 {
        return Err(format!(
            "genesis block must have height 0, got {}",
            block.header.height
        ));
    }
    if block.header.parent_hash != [0u8; 32] {
        return Err("genesis block must have zero parent_hash".to_string());
    }
    if !block.transactions.is_empty() {
        return Err("mainnet genesis must be fair-launch and contain no transactions".to_string());
    }
    let expected_state_root = aetheris_zkp::build_merkle_root(&[]);
    if block.header.state_root != expected_state_root {
        return Err("genesis state_root must be the empty note/nullifier root".to_string());
    }
    if block.header.difficulty != VDF_DIFFICULTY {
        return Err(format!(
            "genesis difficulty mismatch: expected {}, got {}",
            VDF_DIFFICULTY, block.header.difficulty
        ));
    }
    if block.header.vdf_result != vec![0u8; 32] || block.header.vdf_proof != vec![0u8; 32] {
        return Err("genesis VDF result/proof must be zero placeholders".to_string());
    }
    if !block.header.recursive_proof.is_empty() {
        return Err("genesis recursive proof must be empty".to_string());
    }

    let actual_identity = hex::encode(genesis_identity_hash(block));
    if actual_identity != EXPECTED_GENESIS_HASH {
        return Err(format!(
            "genesis identity mismatch: expected {}, got {}",
            EXPECTED_GENESIS_HASH, actual_identity
        ));
    }

    Ok(())
}

pub fn validate_transaction_public_shape(tx: &Transaction) -> Result<(), String> {
    tx.validate_public_shape()
        .map_err(|e| format!("invalid transaction public shape: {e}"))
}

pub fn validate_transaction_proofs(transactions: &[Transaction]) -> Result<(), String> {
    match aetheris_zkp::ZKProofSystem::batch_verify_transaction_result(transactions) {
        Ok(true) => Ok(()),
        Ok(false) => Err("invalid transaction proof: transaction proof returned false".to_string()),
        Err(e) => Err(format!("invalid transaction proof: {e}")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionValidationContext {
    Mempool,
    Block,
}

pub fn validate_transaction_common(
    tx: &Transaction,
    context: TransactionValidationContext,
) -> Result<(), String> {
    validate_transaction_public_shape(tx)?;

    if context == TransactionValidationContext::Mempool && tx.is_coinbase() {
        return Err("coinbase transactions are not accepted in the mempool".to_string());
    }

    Ok(())
}

pub fn validate_transaction_for_mempool(tx: &Transaction) -> Result<(), String> {
    validate_transaction_common(tx, TransactionValidationContext::Mempool)?;
    validate_transaction_proofs(std::slice::from_ref(tx))
}

pub fn validate_transaction_for_block_public(tx: &Transaction) -> Result<(), String> {
    validate_transaction_common(tx, TransactionValidationContext::Block)
}

pub fn validate_block_transactions_against_state(
    transactions: &[Transaction],
    spent_nullifiers: &HashSet<Nullifier>,
    existing_commitments: &HashSet<Commitment>,
) -> Result<(), String> {
    let mut seen_nullifiers_in_block = HashSet::new();
    let mut seen_commitments_in_block = HashSet::new();
    for tx in transactions {
        validate_transaction_for_block_public(tx)?;
        for nf in &tx.inputs {
            if spent_nullifiers.contains(nf) || !seen_nullifiers_in_block.insert(*nf) {
                return Err("double-spend: nullifier already spent".to_string());
            }
        }
        for output in &tx.outputs {
            if existing_commitments.contains(&output.commitment)
                || !seen_commitments_in_block.insert(output.commitment)
            {
                return Err("duplicate output commitment".to_string());
            }
        }
    }

    let proof_transactions = transactions
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .cloned()
        .collect::<Vec<_>>();
    validate_transaction_proofs(&proof_transactions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aetheris_core::{
        BlockHeader, ShieldedOutput, PROOF_SYSTEM_CANONICAL_SHIELDED_V1,
        PROOF_SYSTEM_LEGACY_CONSERVATION,
    };

    fn locked_fair_launch_genesis() -> Block {
        Block {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                state_root: aetheris_zkp::build_merkle_root(&[]),
                timestamp: 1_771_027_200,
                vdf_result: vec![0u8; 32],
                vdf_proof: vec![0u8; 32],
                height: 0,
                difficulty: VDF_DIFFICULTY,
                recursive_proof: vec![],
            },
            transactions: vec![],
        }
    }

    fn tx_with_proof(proof: Vec<u8>) -> Transaction {
        Transaction {
            inputs: vec![[1u8; 32]],
            outputs: vec![],
            public_amount: 0,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_CANONICAL_SHIELDED_V1,
            proof,
        }
    }

    #[test]
    fn test_validate_genesis_block_accepts_locked_fair_launch_genesis() {
        validate_genesis_block(&locked_fair_launch_genesis()).unwrap();
    }

    #[test]
    fn test_validate_genesis_block_rejects_identity_wrong_timestamp() {
        let mut genesis = locked_fair_launch_genesis();
        genesis.header.timestamp += 1;
        let err = validate_genesis_block(&genesis).unwrap_err();
        assert!(err.contains("genesis identity mismatch"));
    }

    #[test]
    fn test_validate_genesis_block_rejects_legacy_premine_transactions() {
        let mut genesis = locked_fair_launch_genesis();
        genesis.transactions.push(Transaction {
            inputs: vec![],
            outputs: vec![ShieldedOutput {
                commitment: [7u8; 32],
                ephemeral_key: [0u8; 32],
                ciphertext: vec![],
            }],
            public_amount: 1,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_LEGACY_CONSERVATION,
            proof: vec![],
        });
        let err = validate_genesis_block(&genesis).unwrap_err();
        assert!(err.contains("fair-launch"));
    }

    #[test]
    fn test_validate_transaction_for_mempool_rejects_coinbase() {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![ShieldedOutput {
                commitment: [1u8; 32],
                ephemeral_key: [0u8; 32],
                ciphertext: vec![],
            }],
            public_amount: 1,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_LEGACY_CONSERVATION,
            proof: vec![],
        };

        let err = validate_transaction_for_mempool(&tx).unwrap_err();
        assert!(err.contains("coinbase transactions are not accepted"));
    }

    #[test]
    fn test_validate_transaction_for_mempool_rejects_malformed_proof() {
        let err = validate_transaction_for_mempool(&tx_with_proof(b"not-a-proof".to_vec()))
            .unwrap_err();
        assert!(err.contains("invalid transaction proof"));
    }

    #[test]
    fn test_validate_transaction_proofs_accepts_empty_batch() {
        validate_transaction_proofs(&[]).unwrap();
    }

    #[test]
    fn test_validate_transaction_proofs_rejects_malformed_non_coinbase() {
        let err = validate_transaction_proofs(&[tx_with_proof(b"not-a-proof".to_vec())])
            .unwrap_err();
        assert!(err.contains("invalid transaction proof"));
    }

    fn assert_mempool_and_block_reject_non_coinbase(tx: Transaction, expected: &str) {
        let mempool_err = validate_transaction_for_mempool(&tx).unwrap_err();
        assert!(
            mempool_err.contains(expected),
            "mempool error `{mempool_err}` did not contain `{expected}`"
        );

        let block_err = validate_block_transactions_against_state(
            std::slice::from_ref(&tx),
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(
            block_err.contains(expected),
            "block error `{block_err}` did not contain `{expected}`"
        );
    }

    #[test]
    fn test_mempool_block_matrix_rejects_duplicate_nullifier_shape() {
        let mut tx = tx_with_proof(vec![]);
        tx.inputs = vec![[9u8; 32], [9u8; 32]];

        assert_mempool_and_block_reject_non_coinbase(tx, "duplicate input nullifier");
    }

    #[test]
    fn test_mempool_block_matrix_rejects_malformed_non_coinbase_proof() {
        assert_mempool_and_block_reject_non_coinbase(
            tx_with_proof(b"not-a-proof".to_vec()),
            "invalid transaction proof",
        );
    }

    #[test]
    fn test_validate_transaction_for_block_public_rejects_duplicate_nullifier() {
        let mut tx = tx_with_proof(vec![]);
        tx.inputs = vec![[2u8; 32], [2u8; 32]];

        let err = validate_transaction_for_block_public(&tx).unwrap_err();
        assert!(err.contains("duplicate input nullifier"));
    }

    #[test]
    fn test_validate_block_transactions_rejects_cross_tx_duplicate_nullifier() {
        let mut tx_a = tx_with_proof(vec![]);
        tx_a.inputs = vec![[3u8; 32]];
        let mut tx_b = tx_with_proof(vec![]);
        tx_b.inputs = vec![[3u8; 32]];

        let err = validate_block_transactions_against_state(
            &[tx_a, tx_b],
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("double-spend"));
    }

    #[test]
    fn test_validate_block_transactions_rejects_spent_nullifier() {
        let mut tx = tx_with_proof(vec![]);
        tx.inputs = vec![[4u8; 32]];
        let spent = HashSet::from([[4u8; 32]]);

        let err = validate_block_transactions_against_state(&[tx], &spent, &HashSet::new()).unwrap_err();
        assert!(err.contains("double-spend"));
    }

    fn coinbase_with_commitment(commitment: Commitment) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![ShieldedOutput {
                commitment,
                ephemeral_key: [0u8; 32],
                ciphertext: vec![],
            }],
            public_amount: 1,
            fee: 0,
            note_root: [0u8; 32],
            proof_system_version: PROOF_SYSTEM_LEGACY_CONSERVATION,
            proof: vec![],
        }
    }

    #[test]
    fn test_validate_block_transactions_rejects_existing_output_commitment() {
        let tx = coinbase_with_commitment([5u8; 32]);
        let existing = HashSet::from([[5u8; 32]]);

        let err = validate_block_transactions_against_state(
            &[tx],
            &HashSet::new(),
            &existing,
        )
        .unwrap_err();
        assert!(err.contains("duplicate output commitment"));
    }

    #[test]
    fn test_validate_block_transactions_rejects_intra_block_output_commitment_duplicate() {
        let tx_a = coinbase_with_commitment([6u8; 32]);
        let tx_b = coinbase_with_commitment([6u8; 32]);

        let err = validate_block_transactions_against_state(
            &[tx_a, tx_b],
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("duplicate output commitment"));
    }

    #[test]
    fn test_validate_block_transactions_rejects_malformed_non_coinbase_proof() {
        let tx = tx_with_proof(b"not-a-proof".to_vec());

        let err = validate_block_transactions_against_state(
            &[tx],
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap_err();
        assert!(err.contains("invalid transaction proof"));
    }

    #[test]
    fn test_validate_block_transactions_allows_coinbase_without_proof() {
        let tx = coinbase_with_commitment([1u8; 32]);

        validate_block_transactions_against_state(&[tx], &HashSet::new(), &HashSet::new())
            .unwrap();
    }
}
