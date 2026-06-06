//! Phase 1.5 / 1.10: block-level IPA accumulator aggregation.
//!
//! These free functions wrap the per-proof `AccumulatorIPA::accumulate`
//! to provide the block-production and block-validation API used by
//! `aetheris-node` and `aetheris-ffi`.
//!
//! §1.10 adds ed25519-signed accumulator support:
//! - `signed_accumulate_proof` produces 160B signed accumulator bytes
//! - `verify_accumulator_chain` accepts an optional verifying key:
//!   - `Some(pk)` + signed accumulator → O(1) signature check
//!   - `None` → O(n) replay (backward compatible)
//!
//! Trust model: this module inherits the trusted-aggregator model
//! from `accumulator.rs` — see `AccumulatorIPA` docs for details.

use aetheris_zkp::TxCommitments;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use group::GroupEncoding;

use crate::accumulator::{AccumulatorIPA, ACCUMULATOR_SIGNATURE_DOMAIN};

/// Fold one inner proof into the accumulator state and return the
/// serialized new state (unsigned, 96B format).
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

/// Fold one inner proof into the accumulator state and return a
/// **signed** accumulator (160B format with ed25519 signature).
///
/// The aggregator signs `blake3(ACCUMULATOR_SIGNATURE_DOMAIN ||
/// prev_bytes || new_unsigned_bytes)`, binding the transition from
/// the previous state to the new state. A verifier who trusts the
/// aggregator's public key can skip the O(n) ZK replay and instead
/// verify the signature in O(1).
pub fn signed_accumulate_proof(
    accumulator: &[u8],
    proof: &[u8],
    output_commitments: &[[u8; 32]],
    public_amount: i64,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, String> {
    let prev = AccumulatorIPA::from_bytes(accumulator)
        .map_err(|e| format!("accumulator deserialization failed: {:?}", e))?;
    let new_acc = prev
        .clone()
        .accumulate(proof, output_commitments, public_amount)
        .map_err(|e| format!("accumulation failed: {:?}", e))?;

    // Message to sign: blake3(domain || prev_bytes || unsigned_new_bytes)
    let prev_bytes = prev.to_bytes();
    let unsigned_new = new_acc.to_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACCUMULATOR_SIGNATURE_DOMAIN);
    hasher.update(&prev_bytes);
    hasher.update(&unsigned_new);
    let msg = hasher.finalize();

    let sig: ed25519_dalek::Signature = signing_key.sign(msg.as_bytes());
    let signed = new_acc.with_signature(sig.to_bytes());
    signed
        .to_signed_bytes()
        .map_err(|e| format!("signed serialization failed: {:?}", e))
}

/// Full-block accumulator chain verification.
///
/// # O(1) signature mode (fast path)
/// When `aggregator_pubkey` is `Some(pk)` AND `claimed_accumulator`
/// uses the signed wire format (160B with `SIGNED_ACCUMULATOR_WIRE_PREFIX`):
///   1. Deserialize `claimed_accumulator` (extracts signature)
///   2. Verify `pk.signature_is_valid(blake3(domain || prev || claimed_unsigned), sig)`
///   3. If valid → return `true` immediately (trust the aggregator)
///   4. If invalid → fall through to O(n) audit replay
///
/// # O(n) audit replay (slow path)
/// When no pubkey is provided OR the signed check fails, replays every
/// proof from `prev_accumulator` through `tx_proofs` and compares the
/// resulting state to `claimed_accumulator`.
///
/// # Backward compatibility
/// Callers that pass `None` (or use unsigned accumulators) get the
/// original O(n) replay behavior unchanged.
pub fn verify_accumulator_chain(
    claimed_accumulator: &[u8],
    prev_accumulator: &[u8],
    tx_proofs: &[Vec<u8>],
    tx_commitments: &[TxCommitments],
    tx_public_amounts: &[i64],
    aggregator_pubkey: Option<&VerifyingKey>,
) -> bool {
    // ── O(1) fast path: signature check ────────────────────────────
    if let Some(pk) = aggregator_pubkey {
        if let Ok(claimed) = AccumulatorIPA::from_bytes(claimed_accumulator) {
            if let Some(sig_bytes) = claimed.signature {
                // Reconstruct the message: domain || prev_bytes || claimed_unsigned_bytes
                let claimed_unsigned = claimed.to_bytes();
                if let Ok(prev) = AccumulatorIPA::from_bytes(prev_accumulator) {
                    let prev_bytes = prev.to_bytes();
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(ACCUMULATOR_SIGNATURE_DOMAIN);
                    hasher.update(&prev_bytes);
                    hasher.update(&claimed_unsigned);
                    let msg = hasher.finalize();

                    if let Ok(sig) = ed25519_dalek::Signature::from_slice(sig_bytes.as_slice()) {
                        use ed25519_dalek::Verifier;
                        if pk.verify(msg.as_bytes(), &sig).is_ok() {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // ── O(n) audit replay ─────────────────────────────────────────
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

    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// Empty-block test: `verify_accumulator_chain` on an empty tx
    /// set should return true (chain is identity, claimed == replayed).
    #[test]
    fn empty_chain_validates() {
        let empty = empty_accumulator();
        let ok = verify_accumulator_chain(&empty, &empty, &[], &[], &[], None);
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
            None,
        );
        assert!(!ok);
    }

    /// Bad-wire-format test: a claimed accumulator that doesn't
    /// deserialize should return false.
    #[test]
    fn bad_wire_format_rejected() {
        let empty = empty_accumulator();
        let bad = b"not_an_accumulator_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let ok = verify_accumulator_chain(bad, &empty, &[], &[], &[], None);
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

    use aetheris_zkp::{ZkProverSystem, ZKProofSystem, create_commitment};

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
            None,
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
            None,
        );
        assert!(ok, "three-tx chain must self-validate (depth=3)");
    }

    /// Multi-block: simulate "block 1" with 2 txs and "block 2" with 2 txs.
    /// Block 2's `prev_accumulator` is Block 1's `claimed_accumulator`.
    /// Verify chain across both blocks.
    #[test]
    fn multi_block_chain_chains_across_blocks() {
        let (p1a, c1a) = make_tx_proof(40, 1, 0);
        let (p1b, c1b) = make_tx_proof(60, 2, 0);
        let block1_prev = empty_accumulator();
        let block1_acc1 = accumulate_proof(&block1_prev, &p1a, &c1a, 0).expect("b1 acc1");
        let block1_claimed = accumulate_proof(&block1_acc1, &p1b, &c1b, 0).expect("b1 acc2");

        assert!(
            verify_accumulator_chain(
                &block1_claimed,
                &block1_prev,
                &[p1a.clone(), p1b.clone()],
                &[c1a.clone(), c1b.clone()],
                &[0, 0],
                None,
            ),
            "block 1 chain must self-validate"
        );

        let (p2a, c2a) = make_tx_proof(30, 3, 0);
        let (p2b, c2b) = make_tx_proof(70, 4, 0);
        let block2_acc1 = accumulate_proof(&block1_claimed, &p2a, &c2a, 0).expect("b2 acc1");
        let block2_claimed = accumulate_proof(&block2_acc1, &p2b, &c2b, 0).expect("b2 acc2");

        assert!(
            verify_accumulator_chain(
                &block2_claimed,
                &block1_claimed,
                &[p2a.clone(), p2b.clone()],
                &[c2a.clone(), c2b.clone()],
                &[0, 0],
                None,
            ),
            "block 2 chain must self-validate (chained on block 1)"
        );

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
        let ok = verify_accumulator_chain(&prev, &prev, &[], &[], &[], None);
        assert!(ok, "empty block must self-validate (no-op)");
    }

    /// Tampered proof: take a real proof, flip the last byte. The chain
    /// verify must reject.
    #[test]
    fn invalid_proof_byte_rejected() {
        let (mut proof, commitments) = make_tx_proof(100, 1, 0);
        let last = proof.len() - 1;
        proof[last] ^= 0xFF;
        let prev = empty_accumulator();
        let claimed_result = accumulate_proof(&prev, &proof, &commitments, 0);
        if let Ok(claimed) = claimed_result {
            let ok = verify_accumulator_chain(
                &claimed,
                &prev,
                &[proof],
                &[commitments],
                &[0],
                None,
            );
            assert!(!ok, "tampered proof must cause chain verify to reject");
        }
    }

    // ─── §1.10: Signed accumulator tests ───────────────────────────

    /// Signed single-tx chain: prove → signed_accumulate → O(1) verify
    /// with the correct pubkey.
    #[test]
    fn signed_single_tx_chain_validates() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let (proof, commitments) = make_tx_proof(100, 1, 0);
        let prev = empty_accumulator();

        let claimed = signed_accumulate_proof(&prev, &proof, &commitments, 0, &sk)
            .expect("signed accumulate must succeed");

        let ok = verify_accumulator_chain(
            &claimed,
            &prev,
            &[proof],
            &[commitments],
            &[0],
            Some(&vk),
        );
        assert!(ok, "signed single-tx chain must validate in O(1)");
    }

    #[test]
    fn signed_chain_wrong_pubkey_falls_back_to_on_replay() {
        let sk = test_signing_key();
        let wrong_sk = test_signing_key();
        let wrong_vk = wrong_sk.verifying_key();
        let correct_vk = sk.verifying_key();

        let (proof, commitments) = make_tx_proof(100, 1, 0);
        let prev = empty_accumulator();

        let claimed = signed_accumulate_proof(&prev, &proof, &commitments, 0, &sk)
            .expect("signed accumulate");

        // Correct pubkey → O(1) passes
        assert!(
            verify_accumulator_chain(&claimed, &prev, &[proof.clone()], &[commitments.clone()], &[0], Some(&correct_vk)),
            "correct pubkey must pass O(1)"
        );

        // Wrong pubkey → O(1) fails, falls through to O(n) replay which
        // still passes because the accumulator is honestly accumulated.
        assert!(
            verify_accumulator_chain(&claimed, &prev, &[proof], &[commitments], &[0], Some(&wrong_vk)),
            "wrong pubkey falls through to O(n) replay (accumulator is valid)"
        );
    }

    #[test]
    fn signed_verify_falls_back_to_unsigned_on_unsigned_input() {
        let vk = test_signing_key().verifying_key();

        let (proof, commitments) = make_tx_proof(100, 1, 0);
        let prev = empty_accumulator();

        let claimed = accumulate_proof(&prev, &proof, &commitments, 0)
            .expect("unsigned accumulate");

        let ok = verify_accumulator_chain(
            &claimed,
            &prev,
            &[proof],
            &[commitments],
            &[0],
            Some(&vk),
        );
        assert!(ok, "unsigned input must fall back to O(n) and pass");
    }

    /// Signed accumulator with tampered claimed bytes (corrupted Q):
    /// O(1) fast path passes (signature is valid for the corrupt state),
    /// but O(n) replay detects the mismatch.
    #[test]
    fn signed_accumulator_tampered_rejected_by_on_replay() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let (proof, commitments) = make_tx_proof(100, 1, 0);
        let prev = empty_accumulator();

        let mut claimed = signed_accumulate_proof(&prev, &proof, &commitments, 0, &sk)
            .expect("signed accumulate");

        // Corrupt one byte of the Q field in the signed accumulator
        // (offset 28 = prefix.len, flip a byte in the Q encoding)
        let offset = crate::accumulator::SIGNED_ACCUMULATOR_WIRE_PREFIX.len();
        claimed[offset] ^= 0x01;

        // O(1) fast path: signature is still valid (the signature was
        // made over the ORIGINAL state, but O(1) only verifies that
        // sig(domain || prev || claimed_unsigned) matches — it trusts
        // the aggregator. Since we corrupted `claimed` after signing,
        // the O(1) check recomputes claimed_unsigned from the corrupt
        // bytes, which won't match the original. But the signature was
        // over the ORIGINAL bytes, not the corrupt ones... Wait, the
        // O(1) check uses `AccumulatorIPA::from_bytes(claimed)` to get
        // the claimed struct, then `claimed.to_bytes()` to get the
        // unsigned version, then verifies sig. Since we corrupted Q,
        // `from_bytes` deserializes the corrupt Q, `to_bytes()` produces
        // different unsigned bytes, and the signature won't match.
        // So O(1) should fail, and O(n) also fails.
        let ok_fast = verify_accumulator_chain(
            &claimed,
            &prev,
            &[proof.clone()],
            &[commitments.clone()],
            &[0],
            Some(&vk),
        );
        assert!(!ok_fast, "tampered claimed must fail O(1) sig check");

        // O(n) replay: also fails (corrupt Q doesn't match replayed state)
        let ok_replay = verify_accumulator_chain(
            &claimed,
            &prev,
            &[proof],
            &[commitments],
            &[0],
            None,
        );
        assert!(!ok_replay, "tampered claimed must also fail O(n) replay");
    }

    #[test]
    fn signed_three_tx_chain_validates() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        let (p1, c1) = make_tx_proof(50, 1, 0);
        let (p2, c2) = make_tx_proof(75, 2, 0);
        let (p3, c3) = make_tx_proof(100, 3, 0);

        let prev = empty_accumulator();
        let acc1 = signed_accumulate_proof(&prev, &p1, &c1, 0, &sk).expect("acc1");
        let acc2 = signed_accumulate_proof(&acc1, &p2, &c2, 0, &sk).expect("acc2");
        let acc3 = signed_accumulate_proof(&acc2, &p3, &c3, 0, &sk).expect("acc3");

        assert!(
            verify_accumulator_chain(&acc1, &prev, &[p1.clone()], &[c1.clone()], &[0], Some(&vk)),
            "step 1 signed"
        );
        assert!(
            verify_accumulator_chain(&acc2, &acc1, &[p2.clone()], &[c2.clone()], &[0], Some(&vk)),
            "step 2 signed"
        );
        assert!(
            verify_accumulator_chain(&acc3, &acc2, &[p3], &[c3], &[0], Some(&vk)),
            "step 3 signed"
        );
    }
}
