# B-2: Native IPA Accumulation on Vesta — ✅ COMPLETE

> **Status**: <span style="color:green">Complete</span> (commit 59cd2c9)
> **Test result**: 155/155 passed, workspace clean

**Binding document**: `protocol_design_ruling.md` §1.1, §4 P1
**Supersedes**: `docs/in_circuit_ipa_verifier.md` (§1.12 NonNativeChip-based design)
**Date**: 2026-06-09
**Status**: Active

---

## Architecture

### Curve Roles (Pasta 2-cycle)

| Layer | Curve | Circuit Field | Purpose |
|-------|-------|--------------|---------|
| Outer ZK | Pallas | `Circuit<Fp>` | Value conservation, membership, nullifier |
| Recursive | **Vesta** | **`Circuit<Fq>`** | IPA accumulation (this plan) |

### Key Property

In `Circuit<Fq>` (Vesta base field):
- **Fq scalars** (Pallas scalar field, IPA challenges, `a`, `r'`, `x_i`) → **native** ✅
- **Vesta point ops** (accumulator `Q`, `π_commitment` mapped to Vesta) → **native** ✅
- Pallas point coordinates (Fp) → non-native (only in final verification equation)
- **NonNativeFqChip entirely eliminated** → replaced by native Fq operations

### Comparison: Old vs New

| Dimension | Old §1.12 (`Circuit<Fp>` + NonNativeFq) | B-2 (`Circuit<Fq>` native) |
|-----------|----------------------------------------|----------------------------|
| Fq scalar mul | NonNativeFqScalarMul (~46K rows) | Native field mul (1 row) |
| Point ops | Native Pallas | Native Vesta |
| Transcript challenges | Non-native Fq derive | Native Fq derive |
| Blake2b gadget | Hardcoded Fp | Generic `F: Field` |
| NonNativeChip | Required (~2500 rows) | **Removed entirely** |
| Estimated rows/scalar_mul | ~46K (2-bit windows) | ~1 (native field) |

---

## Implementation: Atomic Steps (S0–S11)

Each step is <200 lines of new code and independently verifiable.

### Dependency Graph

```
S0 (generic methods)
 ├→ S1 (FqByteAssigner) → S2 (FqWordDecoder) → S3 (FqCompress) → S4 (FqSqueeze) → S5 (transcript e2e)
 └→ S6 (VestaFold) → S7 (IpaCircuit) → S8 (identity) → S9 (point_eq) → S10 (e2e test)
                                                                              └→ S11 (cleanup)
```

S3 depends on S0 being done first; S1–S2 can be done before S0.
S6–S10 form the Phase 5 chain, independent of S1–S5 except for circuit assembly (S7).

---

### S0 — Generic Methods on `Blake2bCompressionCircuitChip`

**Goal**: Make all assignment/constraint methods (except `constrain_challenge_scalar`) generic over `F: PrimeField + From<u64>`.

**Why**: 20+ methods in `Blake2bCompressionCircuitChip` use `Layouter<Fp>` but do not actually depend on `self.fq` (NonNativeFqChip). Making them generic lets `Circuit<Fq>` reuse them directly, eliminating ~1000 lines of code duplication.

**Mechanism**: Add `impl<F: PrimeField + From<u64>> Blake2bCompressionCircuitChip` block with the same methods, `Fp` → `F`.

**Files**: `transcript_blake2b_circuit.rs`

**Verification**: `cargo check --workspace` + `cargo test -p aetheris-recursive` (same 147 pass / 12 pre-existing fail).

---

### S1 — `FqByteAssigner`

**Goal**: Assign u8 bytes as Fq cells with 8-bit range check via `FqRangeCheckChip`.

**New file**: `vesta_transcript.rs`

| Sub-step | Change |
|----------|--------|
| 1.1 | `FqByteAssigner::assign_byte(layouter, value: u8) -> Limb<Fq>` — assign advice + call `FqRangeCheckChip::range_check` |
| 1.2 | `FqByteAssigner::assign_bytes(layouter, &[u8]) -> Vec<Limb<Fq>>` |

**Verification**: Unit test: 3 random bytes assigned, range-checked, challenge equals host.

**Size**: ~80 lines.

---

### S2 — `FqWordDecoder`

**Goal**: From 8 `Limb<Fq>` bytes, reconstruct a u64 word using `TranscriptWordConfig`'s decode gate.

**New file**: `vesta_transcript.rs`

| Sub-step | Change |
|----------|--------|
| 2.1 | `assign_word(region, bytes: &[Limb<Fq>; 8]) -> Limb<Fq>` — enable `s_decode`, constrain `Σ byte_i * 2^(8i) = word` |
| 2.2 | Optionally range-check word to 64 bits via `FqRangeCheckChip` |

**Verification**: Unit test: word decomposition roundtrip.

**Size**: ~80 lines.

---

### S3 — `FqCompressBlock`

**Goal**: Assign a single Blake2b compression block trace in `Circuit<Fq>`, reusing S0's generic methods.

**New file**: `vesta_transcript.rs`

| Sub-step | Change |
|----------|--------|
| 3.1 | `assign_state_row(compression, layouter, block, state_in, state_out)` — calls S0 generic |
| 3.2 | Assign round/mix/step traces via S0 generic methods |
| 3.3 | Constrain: message pairs, round chaining, feed-forward XOR |

**Verification**: Unit test: assign one block, verify with host-computed state_out.

**Size**: ~50 lines (the sub-calls are the S0 generic methods).

---

### S4 — `FqSqueezeChallenge`

**Goal**: Derive Fq challenge from 64-byte Blake2b digest using native arithmetic.

**New file**: `vesta_transcript.rs`

**Algorithm**: `challenge = Σ word_i * 2^(64*i) mod Fq`
- Chain of 7 `s_decompose` gates (`target = term1 + term2 * shift`):
  - `acc_0 = word_0 + word_1 * 2^64`
  - `acc_1 = acc_0 + word_2 * 2^128`
  - ...
  - `challenge = acc_6 + word_7 * 2^448`
- Shifts (2^64, 2^128, ..., 2^448 mod Fq) are host-computed fixed-column values

| Sub-step | Change |
|----------|--------|
| 4.1 | Compute shift constants on host |
| 4.2 | `constrain_challenge_scalar_native(layouter, squeeze_row, challenge_witness) -> ()` |
| 4.3 | Copy-constrain `challenge_cell = acc_7_cell` |

**Verification**: Unit test: digest → challenge roundtrip vs `Fq::from_uniform_bytes`.

**Size**: ~100 lines.

---

### S5 — Transcript End-to-End

**Goal**: Full `VestaTranscriptChip` test: absorb 128 bytes → compress → squeeze → derive challenge.

**New file**: `vesta_transcript.rs`

| Sub-step | Change |
|----------|--------|
| 5.1 | `VestaTranscriptConfig { compression: Blake2bCompressionCircuitConfig, word: TranscriptWordConfig, range: FqRangeCheckConfig }` |
| 5.2 | `VestaTranscriptChip { config }` with `configure(meta)` creating all three sub-configs |
| 5.3 | Test: `VestaTranscriptCircuit<Fq>` with `MockProver::verify()` |

**Verification**: `cargo test -p aetheris-recursive -- vesta_transcript::` passes.

**Size**: ~100 lines.

---

### S6 — `VestaFold`

**Goal**: Single IPA folding round: compute intermediate points `G_s = L_i + x_i·R_i + x_i²·R_{i+1}`.

**New file**: `vesta_fold.rs`

| Sub-step | Change |
|----------|--------|
| 6.1 | `fold_round(config, layouter, l_point, r_point, challenge) -> VestaPoint` |
| 6.2 | Uses `VestaEccChip::point_add`, `point_double`, `scalar_mul` |

**Verification**: Unit test: fold L/R points with host-computed challenge, compare to expected.

**Size**: ~150 lines.

---

### S7 — `VestaIpaVerifierCircuit`

**Goal**: Full IPA verification circuit wiring transcript + folding + final check.

**New file**: `vesta_accumulate.rs`

| Sub-step | Change |
|----------|--------|
| 7.1 | `AccumulateConfig`: combine `VestaTranscriptConfig` + `VestaEccConfig` |
| 7.2 | `synthesize`: byte-stream → compress → squeeze challenges → fold rounds → final equation |
| 7.3 | Transcript sequence: `common_point(com)`, `common_scalar(eval)`, for each round: `common_point(L_i)`, `common_point(R_i)`, `squeeze_challenge()` |

**Verification**: Check against host-reference IPA transcript for correct sequencing.

**Size**: ~200 lines.

---

### S8 — scalar_mul Identity Handling

**Goal**: Handle `s = 0` case in `scalar_mul` (result is identity `O`).

**File**: `vesta_ecc.rs`

| Sub-step | Change |
|----------|--------|
| 8.1 | When scalar = 0, output identity flag |
| 8.2 | Add `assert_identity` gate or skip on_curve check when result is (0,0) |

**Verification**: Unit test: `scalar_mul(0, G) = O`.

**Size**: ~50 lines.

---

### S9 — `VestaPointEq`

**Goal**: Gate to assert two Vesta points are equal (coordinate-wise + identity).

**File**: `vesta_ecc.rs`

| Sub-step | Change |
|----------|--------|
| 9.1 | `constrain_equal_points(layouter, a: &VestaPoint, b: &VestaPoint)` — constrain_equal x and y |
| 9.2 | Identity handling: both (0,0) or both on-curve and equal |

**Verification**: Unit test.

**Size**: ~50 lines.

---

### S10 — IPA Accumulation End-to-End

**Goal**: Full integration test: valid IPA proof accepted, corrupted proof rejected.

**Files**: `vesta_fold.rs` + `vesta_accumulate.rs`

| Sub-step | Change |
|----------|--------|
| 10.1 | Generate valid IPA proof on host (via `ipa_transcript.rs` or manual) |
| 10.2 | `MockProver<Fq>::run()` → accepts |
| 10.3 | Corrupt challenge → rejects |
| 10.4 | Corrupt L/R points → rejects |

**Verification**: `cargo test -p aetheris-recursive -- vesta_accumulate::`.

**Size**: ~100 lines.

---

### S11 — Cleanup

**Goal**: Remove doomed NonNativeChip files.

| File | Action |
|------|--------|
| `non_native_fq.rs` | Delete |
| `non_native_mul.rs` | Delete |
| `ipa_verifier_circuit.rs` | Delete |
| `ipa_fold.rs` | Delete |
| `lib.rs` | Remove NonNativeChip, EccChip, PoseidonChip exports |

**Verification**: `cargo check --workspace` + `cargo test --workspace --lib`.

---

## Current Status

| Step | Status | Note |
|------|--------|------|
| S0 | 🔴 **Not started** | Pre-requisite for all downstream Fq work |
| S1 | 🔴 Not started | Blocked on S0? No — can be built independently |
| S2 | 🔴 Not started | Depends on S1 |
| S3 | 🔴 Not started | Depends on S0 |
| S4 | 🔴 Not started | Independent of S0 (uses `s_decompose` on Blake2b config) |
| S5 | 🔴 Not started | Depends on S1–S4 |
| S6 | 🔴 Not started | Depends on Phase 3 (done) |
| S7 | 🔴 Not started | Depends on S5 + S6 |
| S8 | 🔴 Not started | Low priority |
| S9 | 🔴 Not started | Low priority |
| S10 | 🔴 Not started | Depends on S7 + S8 + S9 |
| S11 | 🔴 Not started | Only after S10 passes |

### Already Done (previous phases)

| Work | Status |
|------|--------|
| `Limb<F>` generic | ✅ Done |
| Row types (`AssignedBlake2bStateRow<F>` etc.) | ✅ Done (were already generic) |
| `Blake2bCompressionCircuitChip::configure<F>` | ✅ Done |
| `TranscriptWordChip::configure<F>` | ✅ Done |
| `FqRangeCheckChip` + 2 tests | ✅ Done (`vesta_range.rs`) |
| `VestaEccChip` — on_curve, add, double, select, scalar_mul (6 tests) | ✅ Done (`vesta_ecc.rs`) |
| `ipa_verifier_circuit` test failures (12 pre-existing, K=17 overflow) | ⚠️ Known, will be deleted in S11 |

---

## Key Constraints

1. **S0 must come first** — without it, S3 (Fq compression) requires duplicating 800+ lines.
2. **S1/S2 are independent of S0** — `FqByteAssigner`/`FqWordDecoder` only depend on `TranscriptWordConfig` and `FqRangeCheckConfig`, not on `Blake2bCompressionCircuitChip`.
3. **S4 is independent of S0** — uses `s_decompose` columns on the config directly.
4. **S6–S10 (Phase 5 chain) are independent of S1–S5 (transcript chain)** — they merge at S7.
5. **Phase 3 (Vesta EC ops) is done** — S6 starts from it.
6. **All 12 pre-existing test failures are in doomed files** — do not block any step.

## Execution Order

```
1. S0  — generic Blake2b methods        [refactor, 0 new tests]
2. S4  — native Fq challenge scalar     [new, ~100 lines]
3. S1  — Fq byte assigner               [new, ~80 lines]
4. S2  — Fq word decoder                [new, ~80 lines]
5. S3  — Fq compress block              [new, ~50 lines, needs S0]
6. S5  — VestaTranscript end-to-end     [new, ~100 lines, needs S1–S4]
7. S6  — Vesta fold round               [new, ~150 lines]
8. S7  — Vesta IPA verifier circuit     [new, ~200 lines, needs S5 + S6]
9. S8  — identity handling              [fix, ~50 lines]
10. S9 — point equality gate             [new, ~50 lines]
11. S10 — IPA e2e test                   [new, ~100 lines, needs S7–S9]
12. S11 — cleanup                        [delete files]
```

---

## What Happens to Existing Code

| Component | Fate | Reason |
|-----------|------|--------|
| `transcript_blake2b_circuit.rs` | **Refactored** (S0) | Add generic impl block |
| `transcript_blake2b.rs` | **Kept** | Host-side types are field-agnostic |
| `transcript_blake2b_compression.rs` | **Kept** | Pure u64 trace, field-agnostic |
| `transcript_words.rs` | **Kept** | `configure<F>` already generic |
| `transcript_bytes.rs` | **Kept** | Will be deleted in Phase 6 along with NonNativeFqChip |
| `non_native_fq.rs` | **Deleted** (S11) | Replaced by native Fq ops |
| `non_native_mul.rs` | **Deleted** (S11) | Replaced by native Vesta point ops |
| `ipa_verifier_circuit.rs` | **Deleted** (S11) | Based on NonNativeChip; B-2 replaces it |
| `ipa_fold.rs` | **Deleted** (S11) | Based on NonNativeChip |
| `ipa_transcript.rs` | **Kept** | Host-side reference semantics |
| `vesta_range.rs` | **Kept** | New — native Fq range check |
| `vesta_ecc.rs` | **Enhanced** | Add S8 + S9 |
| `vesta_transcript.rs` | **New** (S1–S5) | Vesta transcript chip |
| `vesta_fold.rs` | **New** (S6) | Folding round |
| `vesta_accumulate.rs` | **New** (S7, S10) | Full IPA accumulation circuit |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| S0 generic refactor breaks existing code | Low | High | All existing tests must pass unchanged |
| Vesta EC ops need more columns than expected | Low | Medium | Only 24 ops needed; column budget generous at K=17 |
| IPA final equation requires Pallas→Vesta point mapping | Medium | High | May need non-native Fp arithmetic for Pallas point coords in Circuit<Fq>; scope is small (~24 point ops) |
| Cross-crate breakage from S11 deletion | Medium | Medium | `lib.rs` exports and `ipa_transcript.rs` use are limited; audit before S11 |
