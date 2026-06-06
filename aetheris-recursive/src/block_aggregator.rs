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
}
