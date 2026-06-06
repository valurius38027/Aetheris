//! Phase 1.5: block-level IPA accumulator aggregation.
//!
//! These free functions wrap the per-proof `AccumulatorIPA::accumulate`
//! to provide the block-production and block-validation API used by
//! `aetheris-node` and `aetheris-ffi`.
//!
//! Architectural rationale: the `ZkProverSystem` trait
//! (`aetheris-zkp/src/trait_.rs`) defines *per-proof* primitives
//! (prove/verify conservation, prove/verify vdf). The accumulator
//! chain is a *higher-level* operation that composes those
//! primitives, so it lives in `aetheris-recursive` (which already
//! depends on `aetheris-zkp`) rather than in the trait itself. This
//! avoids a `aetheris-zkp ↔ aetheris-recursive` cyclic dependency.
//!
//! Trust model: this module inherits the trusted-aggregator model
//! from `accumulator.rs` — see `AccumulatorIPA` docs for details.

use aetheris_zkp::TxCommitments;

use group::GroupEncoding;

use crate::accumulator::AccumulatorIPA;

/// Fold one inner proof into the accumulator state and return the
/// serialized new state.
///
/// On error, returns a human-readable `String` (suitable for FFI /
/// C-ABI error returns) that includes the underlying
/// `AccumulatorError` Debug output.
///
/// # Arguments
/// - `accumulator`: previous block's accumulator bytes
///   (e.g. `AccumulatorIPA::new().to_bytes()` for the genesis block)
/// - `proof`: the inner proof bytes (must start with
///   `b"halo2_ipa_pasta_v1_"` — the `INNER_PROOF_PREFIX`)
/// - `output_commitments`: per-tx output commitments, folded into
///   the Fiat-Shamir challenge (Phase 1.5 / ISSUE-1.4.E)
/// - `public_amount`: the per-tx circuit public input
pub fn accumulate_proof(
    accumulator: &[u8],
    proof: &[u8],
    output_commitments: &[[u8; 32]],
    public_amount: i64,
) -> Result<Vec<u8>, String> {
    let acc = AccumulatorIPA::from_bytes(accumulator)
        .map_err(|e| format!("accumulator deserialization failed: {:?}", e))?;
    let new_acc = acc
        .accumulate(proof, output_commitments, public_amount)
        .map_err(|e| format!("accumulation failed: {:?}", e))?;
    Ok(new_acc.to_bytes())
}

/// Full-block accumulator chain verification.
///
/// Replays the entire chain from `prev_accumulator` through every
/// `proof` in `tx_proofs` and compares the resulting state to
/// `claimed_accumulator` (transcript-equal; Q and depth are also
/// equal as a side-effect of the deterministic update).
///
/// Returns `true` iff:
/// 1. `tx_proofs`, `tx_commitments`, `tx_public_amounts` all have the
///    same length
/// 2. `prev_accumulator` and `claimed_accumulator` deserialize as
///    valid accumulator states
/// 3. The replayed state (after folding all proofs) is bit-equal to
///    the claimed state
///
/// This is the **block validator** entry point. Used by
/// `aetheris-node/src/state.rs` (replace the old Merkle-based
/// `verify_aggregate` call).
pub fn verify_accumulator_chain(
    claimed_accumulator: &[u8],
    prev_accumulator: &[u8],
    tx_proofs: &[Vec<u8>],
    tx_commitments: &[TxCommitments],
    tx_public_amounts: &[i64],
) -> bool {
    if tx_proofs.len() != tx_commitments.len() || tx_proofs.len() != tx_public_amounts.len() {
        return false;
    }
    let mut acc = match AccumulatorIPA::from_bytes(prev_accumulator) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[verify_accumulator_chain] prev deserialize failed: {:?}", e);
            return false;
        }
    };
    for ((proof, commitments), public_amount) in tx_proofs
        .iter()
        .zip(tx_commitments.iter())
        .zip(tx_public_amounts.iter())
    {
        match acc.accumulate(proof, commitments, *public_amount) {
            Ok(new_acc) => acc = new_acc,
            Err(e) => {
                eprintln!("[verify_accumulator_chain] step failed: {:?}", e);
                return false;
            }
        }
    }
    let claimed = match AccumulatorIPA::from_bytes(claimed_accumulator) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[verify_accumulator_chain] claimed deserialize failed: {:?}", e);
            return false;
        }
    };
    acc.transcript == claimed.transcript
        && acc.depth == claimed.depth
        && acc.Q.to_bytes() == claimed.Q.to_bytes()
}

/// Convenience: return the canonical empty accumulator state bytes
/// (genesis sentinel for the IPA accumulator chain).
///
/// Equivalent to `AccumulatorIPA::new().to_bytes()` (96 bytes:
/// 28B prefix + 32B identity Q + 32B genesis transcript + 4B depth=0).
pub fn empty_accumulator() -> Vec<u8> {
    AccumulatorIPA::new().to_bytes()
}

/// Re-export of `AccumulatorError` for callers that want to match
/// specific error variants.
pub use crate::accumulator::AccumulatorError as AggregatorError;

#[cfg(test)]
mod tests {
    use super::*;


    /// Empty-block test: `verify_accumulator_chain` on an empty tx
    /// set should return true (chain is identity, claimed == replayed).
    #[test]
    fn empty_chain_validates() {
        let empty = empty_accumulator();
        let ok = verify_accumulator_chain(&empty, &empty, &[], &[], &[]);
        assert!(ok, "empty chain must self-validate");
    }

    /// Length-mismatch test: mismatched input arrays should return
    /// false without panicking.
    #[test]
    fn mismatched_lengths_rejected() {
        let empty = empty_accumulator();
        let ok = verify_accumulator_chain(
            &empty,
            &empty,
            &[b"halo2_ipa_pasta_v1_".to_vec()],
            &[],
            &[],
        );
        assert!(!ok);
    }

    /// Bad-wire-format test: a claimed accumulator that doesn't
    /// deserialize should return false.
    #[test]
    fn bad_wire_format_rejected() {
        let empty = empty_accumulator();
        let bad = b"not_an_accumulator_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let ok = verify_accumulator_chain(bad, &empty, &[], &[], &[]);
        assert!(!ok);
    }

    /// Genesis accumulation: `accumulate_proof` on a malformed proof
    /// should return Err (not panic), even when called from FFI.
    #[test]
    fn accumulate_proof_bad_proof_returns_err() {
        let empty = empty_accumulator();
        let bad_proof = b"not_a_proof";
        let result = accumulate_proof(&empty, bad_proof, &[], 0);
        assert!(result.is_err());
    }

    // ─── ISSUANCE-1.4.C: happy-path accumulator integration tests ──────
    //
    // Phase 1.8: end-to-end exercise of `accumulate_proof` +
    // `verify_accumulator_chain` with REAL ZK proofs (not synthetic bytes).
    // Uses `aetheris_zkp::ZKProofSystem::prove_conservation` to construct
    // properly-prefixed inner proofs that pass the accumulator's
    // `INNER_PROOF_PREFIX` check at `accumulator.rs:134`.

    use aetheris_zkp::{ZkProverSystem, ZKProofSystem, create_commitment};

    /// Build a real (proof, commitments) pair for a single conservation tx.
    /// Local test helper — no public API.
    fn make_tx_proof(amount: u64, blinding_seed: u8, public_amount: i64) -> (Vec<u8>, Vec<[u8; 32]>) {
        let blinding = [blinding_seed; 32];
        let commitment = create_commitment(amount, &blinding);
        let proof = ZKProofSystem::prove_conservation(
            &[amount],
            &[amount],
            &[blinding],
            &[blinding],
            &[commitment],
            public_amount,
        );
        (proof, vec![commitment])
    }

    /// Single-tx chain: prove → accumulate → verify roundtrip.
    #[test]
    fn single_tx_chain_validates() {
        let (proof, commitments) = make_tx_proof(100, 1, 0);
        let prev = empty_accumulator();

        let claimed = accumulate_proof(&prev, &proof, &commitments, 0)
            .expect("single-tx accumulate must succeed");

        let ok = verify_accumulator_chain(
            &claimed,
            &prev,
            &[proof],
            &[commitments],
            &[0],
        );
        assert!(ok, "single-tx chain must self-validate");
    }

    /// Three-tx chain: prove 3 distinct txs → accumulate sequentially →
    /// verify the final claim against the replayed chain.
    #[test]
    fn three_tx_chain_validates() {
        let (p1, c1) = make_tx_proof(50, 1, 0);
        let (p2, c2) = make_tx_proof(75, 2, 0);
        let (p3, c3) = make_tx_proof(100, 3, 0);

        let prev = empty_accumulator();
        let acc1 = accumulate_proof(&prev, &p1, &c1, 0).expect("acc1");
        let acc2 = accumulate_proof(&acc1, &p2, &c2, 0).expect("acc2");
        let acc3 = accumulate_proof(&acc2, &p3, &c3, 0).expect("acc3");

        let ok = verify_accumulator_chain(
            &acc3,
            &prev,
            &[p1, p2, p3],
            &[c1, c2, c3],
            &[0, 0, 0],
        );
        assert!(ok, "three-tx chain must self-validate (depth=3)");
    }

    /// Multi-block: simulate "block 1" with 2 txs and "block 2" with 2 txs.
    /// Block 2's `prev_accumulator` is Block 1's `claimed_accumulator`.
    /// Verify chain across both blocks.
    #[test]
    fn multi_block_chain_chains_across_blocks() {
        // Block 1: two txs
        let (p1a, c1a) = make_tx_proof(40, 1, 0);
        let (p1b, c1b) = make_tx_proof(60, 2, 0);
        let block1_prev = empty_accumulator();
        let block1_acc1 = accumulate_proof(&block1_prev, &p1a, &c1a, 0).expect("b1 acc1");
        let block1_claimed = accumulate_proof(&block1_acc1, &p1b, &c1b, 0).expect("b1 acc2");

        // Verify block 1 in isolation
        assert!(
            verify_accumulator_chain(
                &block1_claimed,
                &block1_prev,
                &[p1a.clone(), p1b.clone()],
                &[c1a.clone(), c1b.clone()],
                &[0, 0],
            ),
            "block 1 chain must self-validate"
        );

        // Block 2: two more txs, chained on block 1's claim
        let (p2a, c2a) = make_tx_proof(30, 3, 0);
        let (p2b, c2b) = make_tx_proof(70, 4, 0);
        let block2_acc1 = accumulate_proof(&block1_claimed, &p2a, &c2a, 0).expect("b2 acc1");
        let block2_claimed = accumulate_proof(&block2_acc1, &p2b, &c2b, 0).expect("b2 acc2");

        // Verify block 2 with all 4 tx proofs across the chain (clone first
        // because we'll reuse these proofs in the cross-block full replay)
        assert!(
            verify_accumulator_chain(
                &block2_claimed,
                &block1_claimed,  // block 2's prev = block 1's claim
                &[p2a.clone(), p2b.clone()],
                &[c2a.clone(), c2b.clone()],
                &[0, 0],
            ),
            "block 2 chain must self-validate (chained on block 1)"
        );

        // Cross-block full replay: replay all 4 txs from the original empty
        // accumulator and compare to block 2's claim. This is what a full-
        // chain validator would do.
        let full_replay_acc1 = accumulate_proof(&block1_prev, &p1a, &c1a, 0).expect("full acc1");
        let full_replay_acc2 = accumulate_proof(&full_replay_acc1, &p1b, &c1b, 0).expect("full acc2");
        let full_replay_acc3 = accumulate_proof(&full_replay_acc2, &p2a, &c2a, 0).expect("full acc3");
        let full_replay = accumulate_proof(&full_replay_acc3, &p2b, &c2b, 0).expect("full acc4");
        assert_eq!(
            full_replay, block2_claimed,
            "full 4-tx replay from genesis must equal block 2's chained claim"
        );
    }

    /// Empty-block degenerate: zero proofs in a "block" — chain should
    /// self-validate (no-op).
    #[test]
    fn empty_block_still_produces_valid_accumulator() {
        let prev = empty_accumulator();
        // empty → verify (already covered by empty_chain_validates; here we
        // also confirm accumulate_proof on an empty accumulator is well-defined
        // when called with empty proof arrays)
        let ok = verify_accumulator_chain(&prev, &prev, &[], &[], &[]);
        assert!(ok, "empty block must self-validate (no-op)");
    }

    /// Tampered proof: take a real proof, flip the last byte. The chain
    /// verify must reject (the cryptographic-region corruption may trigger
    /// VDF::verify's discriminant boundary check introduced in Phase 1.7,
    /// or the final `left == y` gate — either way, must return false).
    #[test]
    fn invalid_proof_byte_rejected() {
        let (mut proof, commitments) = make_tx_proof(100, 1, 0);
        let last = proof.len() - 1;
        proof[last] ^= 0xFF;
        let prev = empty_accumulator();
        // Try to accumulate — should either fail to produce a valid claimed
        // accumulator OR produce one that fails the subsequent verify.
        let claimed_result = accumulate_proof(&prev, &proof, &commitments, 0);
        if let Ok(claimed) = claimed_result {
            let ok = verify_accumulator_chain(
                &claimed,
                &prev,
                &[proof],
                &[commitments],
                &[0],
            );
            assert!(!ok, "tampered proof must cause chain verify to reject");
        }
        // If accumulate_proof itself returned Err, that's also a valid rejection.
    }
}
