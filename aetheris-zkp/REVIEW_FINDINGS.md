# P0.5 Multi-Agent Review Findings

Generated: 2026-06-10 | 112/112 tests passing before fixes

---

## Agent 1 — Cryptographic Soundness (⚠️ WARNINGS)

### ❌ A1-C1: Missing `constrain_equal` between Merkle levels
**Severity**: Critical  
**File**: `aetheris-zkp/src/membership_circuit.rs`  
**Detail**: Each Merkle level's hash output cell must be `constrain_equal` to next level's leaf input cell. Without this, the prover could disconnect levels — e.g., level 1 hash feeds into level 3 while level 2 uses unrelated values. The constraint pool is shared; nothing links sequential levels except the Poseidon preimage resistance (2^128 assumption).  
**Fix**: Capture `hash_cell` each level, pass as `leaf_cell` to next iteration, add `cb.constrain_equal(hash_cell, leaf_cell)`.  
**Applies to**: both `membership_circuit.rs` and `combined_circuit.rs`.

### ⚠️ A1-W1: Missing `bool_check` on position_bits in Merkle region
**File**: `aetheris-zkp/src/membership_circuit.rs`  
**Detail**: `s_select` gate enforces `bit*(1-bit)=0` via soundness of the gate itself, but an explicit `bool_check` selector + constraint adds defense-in-depth and makes intent clear.  
**Fix**: Add `meta.create_gate("bool check", ...)` constrained to Merkle region.

### ⚠️ A1-W2: Misnamed `s_constrain_equal` gate
**File**: `aetheris-zkp/src/halo2_pasta.rs` (line 175) + `aetheris-zkp/src/combined_circuit.rs`  
**Detail**: Gate constrains `b == 0`, named `s_constrain_equal` — misleading. Should be `s_zero_check`.  
**Fix**: Rename everywhere + update doc.

### ⚠️ A1-W3: No negative test for disconnected levels
**File**: `aetheris-zkp/src/membership_circuit.rs` (tests)  
**Detail**: No MockProver test that swaps a middle sibling to break level continuity.  
**Fix**: Add test that feeds correct path but swaps sibling[1] → wrong hash at level 2.

---

## Agent 2 — Code Correctness (⚠️ WARNINGS)

### ❌ A2-C1: Commitment column `advice[3]` unconstrained by gate
**File**: `aetheris-zkp/src/combined_circuit.rs` (line ~66-74)  
**Detail**: `advice[3]` stores `output_commitments` but has no gate constraining `cm_i` to any particular form. Binding relies entirely on instance-column copy constraints — verifier provides the instance, so a malicious prover can set `cm_i` to any value and the copy constraint still passes.  
**Mitigation**: This is inherent to the Halo2 commitment scheme — copy constraints to instance columns are the standard binding mechanism. But for defense-in-depth, a gate could enforce `cm_i == hash(secret)` or similar.

### ❌ A2-C2: `public_amount` > `i64::MAX` overflow
**File**: `aetheris-zkp/src/combined_circuit.rs` (line ~843)  
**Detail**: `let pad = public_amount - sum_out + sum_in` computes in `i64` — overflow when `public_amount > i64::MAX` (positive overflow) or `sum_in - sum_out - public_amount` wrapping produces large negative → circuit sees wrong `z_64`, causing proof to fail silently. `ZKPError::InvalidAmount` should be returned early.  
**Fix**: Add `public_amount.checked_abs()` or validate before computation: `if public_amount > MAX_AMOUNT { return Err(...) }`.

### ⚠️ A2-W1: Naming hazard — `s_constrain_equal` (duplicate of A1-W2)
**Same as A1-W2** — rename to `s_zero_check`.

### ⚠️ A2-W2: `verify_combined_tx` missing `output_commitments.len()` validation
**File**: `aetheris-zkp/src/combined_circuit.rs` (line ~963-980 or similar)  
**Detail**: The function decodes `out_len` from wire prefix but never checks `output_commitments.len() != out_len`. If caller provides fewer/more commitments than the proof expects, instance layout is misaligned and verification may pass incorrectly.  
**Fix**: Add `if output_commitments.len() != out_len { return Err(...) }`.

### ⚠️ A2-W3: `ensure_combined_keys` dummy circuit edge case
**File**: `aetheris-zkp/src/combined_circuit.rs`  
**Detail**: Dummy circuit uses `public_amount = 0, amounts_in = vec![], amounts_out = vec![]` → `sum_in = sum_out = 0` → `h_eval = 0`. The comment references `AMOUNTS_ZERO = Fq::zero()` but this constant is not defined. **Not a runtime bug** (zero is used literally) but a documentation inconsistency.  
**Fix**: Either define `const AMOUNTS_ZERO: Fq = Fq::zero();` or remove the comment.

---

## Agent 3 — Integration & Regression (⚠️ WARNINGS)

### ❌ A3-P1: `mainnet_execution_plan.md` P0.5 outdated
**File**: `mainnet_execution_plan.md`  
**Detail**: Step 3 (Gate-based mux) shows ⏳ (should be ✅, done in C-3). Step 4 (Integration) shows ❌ (should be ✅, done in C-4). Status header at line 86 shows "⏳ 实现中...待接入".  
**Fix**: Update all P0.5 checkboxes and status header.

### ⚠️ A3-W1: 7 critical missing test paths
| Path | File | Notes |
|------|------|-------|
| Combined vs separate circuits comparison | combined_circuit.rs | `prove_combined_tx` vs separate `prove_conservation`+`prove_membership` |
| Swapped instance values (root↔nf) | combined_circuit.rs | `verify_combined_tx` with wrong instance order |
| Wrong depth in wire format | membership_circuit.rs | prefix says depth=2, actual is depth=3 |
| Wrong wire format prefix | halo2_pasta.rs | `halo2_ipa_pasta_v1_` vs membership prefix |
| Combined empty amounts | combined_circuit.rs | `amounts_in=[], amounts_out=[]` |
| Combined depth=1 | combined_circuit.rs | Minimal tree edge case |
| `public_amount = i64::MIN` | combined_circuit.rs | Minimal negative edge case |

### ✅ A3-W2: Public API `prove_membership`/`verify_membership` untested
**File**: `aetheris-zkp/src/halo2_pasta.rs`  
**Detail**: `test_membership_roundtrip_depth_2` was removed (comment at line 1766). No test calls these public functions after C-3 refactor.  
**Fix**: ✅ Added `test_membership_public_api_roundtrip` — roundtrip test that exposed `PREFIX_LEN` off-by-one.

### ✅ A3-W3: `PREFIX_LEN` off-by-one (19 instead of 20)
**File**: `aetheris-zkp/src/halo2_pasta.rs` (line 625)  
**Detail**: `const PREFIX_LEN: usize = 19` but prefix `b"halo2_ipa_member_v1_"` is 20 bytes. Off-by-one caused depth read at wrong offset (607 → should be 606), and inner proof deserialization starting one byte too early → `"invalid point encoding"` error.  
**Fix**: ✅ Changed to `PREFIX_LEN: usize = 20`. Verified all three wire prefixes: `halo2_ipa_member_v1_` (20), `halo2_ipa_pasta_v1_` (19), `halo2_ipa_combined_v1_` (22).

### ⚠️ A3-W4: Membership keygen uncached
**File**: `aetheris-zkp/src/halo2_pasta.rs` (fn `prove_membership`)  
**Detail**: Every `prove_membership` call regenerates VK+PK via `keygen_vk`+`keygen_pk`. For depth=16 this is expensive. Should use `OnceLock<Mutex<HashMap<usize, CachedKeyPair>>>`.  
**Fix**: Add key cache (postpone — not blocking).

### ⚠️ A3-W5: ~200 lines duplicated Poseidon inline hash
**Files**: `membership_circuit.rs:206-431` ↔ `combined_circuit.rs:460-678`  
**Detail**: The inline Poseidon permutation (sbox, MDS, full/partial rounds) is duplicated identically. Any Poseidon bug fix must be applied to both.  
**Fix**: Extract shared helper (postpone — prototype phase acceptable).

---

## Summary

| Priority | ID | Issue | File | Status |
|----------|----|-------|------|--------|
| ~~🔴 High~~ | ~~A1-C1~~ | ~~Missing constrain_equal between Merkle levels~~ | ~~membership_circuit.rs + combined_circuit.rs~~ | ✅ Fixed |
| ~~🔴 High~~ | ~~A2-W2~~ | ~~verify_combined_tx missing len() validation~~ | ~~combined_circuit.rs~~ | ✅ Fixed |
| ~~🔴 High~~ | ~~A1-W2/A2-W1~~ | ~~Rename s_constrain_equal → s_zero_check~~ | ~~combined_circuit.rs, halo2_pasta.rs~~ | ✅ Fixed |
| ~~🟡 Medium~~ | ~~A1-W1~~ | ~~Missing bool_check on position_bits~~ | ~~membership_circuit.rs~~ | ✅ Fixed |
| 🟡 Medium | A2-C2 | public_amount i64 overflow validation | combined_circuit.rs | Not in scope (see note) |
| 🟢 N/A | A2-W3 | AMOUNTS_ZERO comment not found | combined_circuit.rs | ✅ No fix needed |
| ~~🟢 Low~~ | ~~A3-P1~~ | ~~mainnet_execution_plan.md update~~ | ~~mainnet_execution_plan.md~~ | ✅ Fixed |
| 🟢 Low | A3-W1 | 7 missing test paths | combined_circuit.rs | 1hr |
| ~~🟢 Low~~ | ~~A3-W2~~ | ~~prove_membership/verify_membership untested~~ | ~~halo2_pasta.rs~~ | ✅ Fixed — added roundtrip test; exposed PREFIX_LEN=19→20 bug |
| ~~🔴 Critical~~ | ~~A3-W3~~ | ~~PREFIX_LEN off-by-one (19→20)~~ | ~~halo2_pasta.rs:625~~ | ✅ Fixed — prefix `b"halo2_ipa_member_v1_"` is 20 bytes; was 19, shifted depth offset by 1 + corrupt inner proof decode |
| ⏸ Postpone | A3-W4 | Membership keygen cache | halo2_pasta.rs | — |
| ⏸ Postpone | A3-W5 | Poseidon inline hash dedup | membership_circuit.rs + combined_circuit.rs | — |
