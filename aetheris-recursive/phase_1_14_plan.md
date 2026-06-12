# Phase 1.14 — Recursive Proof Production & State Root Binding

> **Status**: S1-S4 ✅ completed (Stage 47); S5 in progress.
> **Depends on**: Phase 1.13 (RecursiveProofCircuit, PallasAccumulateChip, NonNativeFpChip)
> **Goal**: Wire the recursive proof pipeline into the node — block header, consensus verification, miner generation, FFI exposure.

---

## 1. Status Summary

| Step | Component | Status | Evidence |
|------|-----------|--------|----------|
| S1 | `precompute_ipa_witness()` | ✅ Done | `pallas_accumulate.rs:209` |
| S2 | `prove_recursive()` / `verify_recursive_proof()` | ✅ Done | `prove_recursive.rs:32/51` |
| S3 | End-to-end roundtrip test | ✅ Done | `test_prove_and_verify_recursive` |
| S4 | State root as public instance | ✅ Done | `recursive_proof.rs:111-126` |
| S5 | **Node Integration** | 🔜 This phase | — |

---

## 2. S5 — Node Integration Plan

### 2.1 Overview

Bridge the recursive proof system into the node so that every mined block carries a recursive SNARK attesting to its accumulator state + state_root, and every validating node can verify it in O(1).

**Backward compatibility**: `recursive_proof = None` = trusted fallback (current accumulator chain replay). Nodes without recursive verification still work.

---

### 2.2 Sub-Stages

#### S5-a: BlockHeader Extension + Key Storage

**Files**: `aetheris-core/src/lib.rs`, `aetheris-node/src/state.rs`

1. Add `recursive_proof: Option<Vec<u8>>` to `BlockHeader`
2. Include in `block_hash` computation (different hash for Some vs None)
3. Add `recursive_vk: Option<VerifyingKey<EpAffine>>` to `LedgerState`
4. Add `block_recursive_proof: Option<Vec<u8>>` to `LedgerState` (latest block's recursive proof)
5. No consensus change yet — `None` is accepted (backward compatible)

#### S5-b: state.rs Consensus Verification

**File**: `aetheris-node/src/state.rs`

1. In `apply_block_with_validation`: if `block.header.recursive_proof` is `Some`:
   - Call `verify_recursive_proof()` with stored `recursive_vk` and block's `state_root`
   - On failure → reject block
2. If `None`: use existing accumulator chain replay (backward compat)
3. No change to `validate_issuance_rules`

#### S5-c: Miner Recursive Proof Generation

**File**: `aetheris-ffi/src/lib.rs` (two mining paths)

**Background miner**:
1. After folding IPA accumulator (step 4), call `prove_recursive()` with the final accumulator witness + state_root
2. Store result in `block.header.recursive_proof`

**`aetheris_submit_vdf_proof`**:
1. Same: after constructing block, generate recursive proof
2. Include in block header

#### S5-d: FFI C-ABI + Manager Stub Repair

**File**: `aetheris-ffi/src/lib.rs`

New extern "C" functions:
- `aetheris_prove_recursive(accumulator_state_hex: *const c_char, state_root_hex: *const c_char) -> *mut c_char` — returns proof hex or error
- `aetheris_verify_recursive_proof(proof_hex: *const c_char, state_root_hex: *const c_char) -> bool`
- `aetheris_build_recursive_keys() -> bool` — keygen + store in state
- `aetheris_get_recursive_state_root(proof_ptr: *const u8, len: usize, out: *mut [u8; 32]) -> i32` (from §1.16 plan)

Fix stubs:
- `verify_halo2_proof` in `P2PRecursiveManager` → call `verify_recursive_proof()`
- `generate_atomic_proof` → call `prove_recursive()`

#### S5-e: Crate Root Re-exports

**File**: `aetheris-recursive/src/lib.rs`

- Re-export `prove_recursive` functions at crate root for cleaner caller paths

#### S5-f: Integration Tests

- Mine block → recursive proof generated → included in header → verified on apply
- Block without `recursive_proof` still accepted (backward compat)
- Corrupt recursive proof → block rejected
- `cargo check --workspace` + all existing tests pass

---

## 3. Implementation Order

```
S5-a (BlockHeader + KS)  ─→  S5-b (state.rs verify)  ─→  S5-c (miner)  ─→  S5-d (FFI)  ─→  S5-e (re-exports)  ─→  S5-f (tests)
  [core+node]                   [node]                       [ffi]              [ffi]            [recursive]               [all]
```

**Dependency**: S5-a → S5-b → S5-c (S5-d and S5-e can overlap with S5-c).

---

## 4. Verification Checklist

- [ ] `cargo check --workspace` passes
- [ ] `test_prove_and_verify_recursive` still passes (no regression)
- [ ] Block with `recursive_proof = Some(...)` verified by `apply_block_with_validation`
- [ ] Block without `recursive_proof` still accepted (backward compat)
- [ ] Corrupt recursive proof → block rejected
- [ ] FFI C-ABI functions return correct results
- [ ] Background miner produces blocks with valid recursive proofs
- [ ] All existing tests pass
