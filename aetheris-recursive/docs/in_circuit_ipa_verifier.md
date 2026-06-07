# In-Circuit IPA Verifier Gadget — Design Document

**Status**: Draft
**Phase**: §1.12 (research, 2–3 months estimated)
**Depends on**: §1.3 (EccChip, PoseidonChip, GrainLFSR), §1.1 (IPA commitment scheme)
**Prerequisite reading**: `aetheris-zkp/src/ipa/verifier.rs`, `aetheris-zkp/src/ipa/prover.rs`, `aetheris-zkp/src/ipa/commitment.rs`, `aetheris-recursive/src/lib.rs` (EccChip, PoseidonChip)

---

## 1. Problem Statement

Build a Halo2 circuit that verifies an IPA (Inner Product Argument) proof in-circuit, enabling trustless O(1) recursive proof aggregation.

### 1.1 Trust Model Shift

| Current (§1.10) | Target (§1.12–1.13) |
|---|---|
| Trusted aggregator signs accumulator (ed25519 O(1)) | Anyone can verify a constant-size recursive proof |
| O(n) ZK replay as audit fallback | In-circuit IPA verification replaces replay |
| Aggregator must be honest or slashed | Trustless — cryptographic soundness only |

### 1.2 Key Math

The IPA verifier checks that a multi-point opening claim is correct by verifying:

```
P + Σ_i (x_i⁻¹·L_i + x_i·R_i) + (v − a·b)·U − a·G_final − r'·H = 0
```

Where:
- `P` = theta-weighted combination of commitments (public input)
- `L_i, R_i` = round points (from proof, witnesses)
- `x_i` = round challenges (re-derived from Fiat-Shamir transcript)
- `v` = combined claimed evaluation (public input)
- `a` = `a_final` (from proof, witness)
- `b` = recomputed powers of evaluation point (computed in-circuit)
- `G_final` = folded SRS generators (computed in-circuit)
- `r'` = blinding factor (from proof, witness)
- `U, H` = IPA challenge generator, blinding generator (circuit constants)

---

## 2. Pasta 2-Cycle Properties

```
Pallas:  base = Fp, scalar = Fq
Vesta:   base = Fq, scalar = Fp
```

The recursive circuit runs over **Fp** (Vesta scalar field = Pallas base field).

| Operation | Field | Native? |
|-----------|-------|---------|
| Pallas point coords (x, y) | Fp | ✅ Native |
| Pallas point add / double | Fp | ✅ Native |
| Pallas scalar mul (scalar = Fq) | Fq × Pallas(Fp) | ❌ Non-native |
| IPA folding scalars (b, challenges) | Fq | ❌ Non-native |

---

## 3. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    InCircuitIpaVerifier<Fp>                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────────┐ │
│  │ NonNativeFq   │    │ NonNativeFqScalar│    │ IpaFoldingChip  │ │
│  │ Arithmetic    │◄── │ Mul (Pasta point)│    │ (fold G + b)   │ │
│  │ (add,mul,inv) │    │ × Fq scalar)     │    │                │ │
│  └──────────────┘    └──────────────────┘    └────────────────┘ │
│         ▲                      ▲                      ▲          │
│         │                      │                      │          │
│  ┌──────┴──────────────────────┴──────────────────────┴──────┐   │
│  │                     IpaTranscript                          │   │
│  │         (PoseidonChip 3,2 — Fiat-Shamir in-circuit)       │   │
│  └───────────────────────────────────────────────────────────┘   │
│         ▲                                                       │
│         │                                                       │
│  ┌──────┴──────────────────────────────────────────────────┐    │
│  │  EccChip (point add, double, select, assert_on_curve)   │    │
│  │  — FULLY REUSABLE FROM PHASE 1.3                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Public inputs: P_combined, v, point, k                          │
│  Witness: L_i, R_i, a_final, r_prime                             │
│  Constants: G[0..n], H, U                                        │
│  Output: single bit (accept/reject)                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Design

### 4.1 NonNativeFqChip

#### 4.1.1 Fq Element Representation

Represent an Fq element as **3 Fp limbs** of 85 bits each (255 total, with headroom for carries).

```
Fq_value = limb_0 + limb_1 · 2⁸⁵ + limb_2 · 2¹⁷⁰
```

- Each limb is constrained to `< 2⁸⁵` via range check
- 85 bits leaves 170 bits of headroom in Fp (~255 bits) for carry accumulation
- 3 limbs × 85 bits = 255 bits (covers full Fq range)

```rust
pub struct FqLimb {
    pub value: Value<Fp>,
    pub cell: Option<Cell>,
}
pub struct FqElem {
    pub limbs: [FqLimb; 3],
    // Whether this element's value is canonically reduced mod Fq
    pub reduced: bool,
}
```

#### 4.1.2 Operations

| Operation | Rows | Description |
|-----------|------|-------------|
| `add(a, b) -> c` | ~12 | Schoolbook add with carry propagation + modular reduction |
| `sub(a, b) -> c` | ~12 | Schoolbook sub with borrow |
| `mul(a, b) -> c` | ~36 | Schoolbook multiply (3×3 = 9 partial products), reduce to 3 limbs |
| `neg(a) -> c` | ~8 | sub(0, a) |
| `eq(a, b) -> bool` | ~12 | Constrain all 3 limbs equal |
| `from_fp(fp) -> FqElem` | ~3 | Witness as 3 limbs, check `fp == limb_0 + limb_1·2⁸⁵ + limb_2·2¹⁷⁰` + range checks |
| `to_fp_safe(elem) -> Fp` | ~3 | Assert value fits in 1 Fp → output lower 255 bits |
| `invert(a) -> b` | ~7650 | Fermat: `a^{q-2}` using mul chains (255 squaring + ~240 multiplications) |

**Modular reduction** after multiplication:
```
result = product mod q_pallas
```
Using precomputed `q_pallas` constant in 3 limbs, subtract until result < q.

#### 4.1.3 Column Layout

```
┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│ a0  │ a1  │ a2  │ b0  │ b1  │ b2  │ c0  │ c1  │ c2  │  Advice columns
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
  s_add  s_mul  s_range  Selectors (fixed columns)
```

### 4.2 NonNativeFqScalarMul

Implements `s * P` where `s` is a non-native Fq element and `P` is a Pallas point (native EcPoint).

#### Strategy: Windowed double-and-add (4-bit windows, 64 windows for 255 bits)

1. Decompose `s` into 64 nibbles (4 bits each)
2. For each nibble: load precomputed `[0]P, [1]P, ..., [15]P` via lookup table
3. Double 4 times, add looked-up point

```
result = 0
for i in 0..64:
    for _ in 0..4:
        result = double(result)
    table_entry = lookup(nibble[i], base_table[i])
    result = add(result, table_entry)
```

#### Optimization: Share base table across all rounds

For the G folding, the same `g[j+half]` points are used repeatedly with different `x_inv` scalars. Precompute 4-bit window tables for all `g` points at `configure()` time.

This is essentially what `EccChip::fixed_base_scalar_mul` already does, but the scalar is non-native Fq instead of Fp. The lookup table mechanism is the same — only the scalar decomposition differs.

```rust
pub struct NonNativeFqScalarMulChip {
    ecc: EccChip,  // reuse point add/double
    // Additional columns for scalar decomposition
    nibble: Column<Advice>,
    s_decompose: Selector,
}
```

#### Estimated cost: ~200 rows per scalar mul

Per 4-bit window:
- 4 doubles (EccChip: ~6 rows each) = 24 rows
- 1 lookup + add (EccChip: ~12 rows) = 12 rows
- 1 nibble decomposition check = 2 rows
Total: ~38 rows × 64 windows = ~2432 rows per scalar mul

But using precomputed window tables (reusing `EccChip`'s `load_fixed_table` + `fixed_base_scalar_mul` pattern) brings this down significantly — the window lookup is just a table read, and the 4 doubles are similar.

**Optimized estimate**: using `EccChip::fixed_base_scalar_mul` approach directly but with non-native scalar decomposition: ~600–800 rows per scalar mul.

### 4.3 IpaFoldingChip

The folding chip performs the IPA recursive halving:

```
for round in 0..k:
    x_inv = challenges[round].invert()   // NonNativeFq.invert
    half = n >> (round + 1)
    par_for j in 0..half:
        b_new[j]  = b[j] + x_inv * b[j + half]        // NonNativeFq add + mul
        g_new[j]  = g[j] + scalar_mul(g[j+half], x_inv)  // NonNativeFqScalarMul + point add
```

For `k=10` (n=1024):
- Round 0: 512 iterations, each: 1 mul + 1 add (Fq), 1 scalar mul + 1 point add
- Round 1: 256 iterations
- ...
- Round 9: 1 iteration

Total: 1023 iterations → **1023 non-native scalar muls + 1023 point adds**

**This is the dominant cost.** At ~800 rows per scalar mul, total = ~818k rows just for G folding.

For `k=8` (n=256): ~255 iterations → ~204k rows.

#### Optimization: batch invert

Use Montgomery's trick to compute all `k` inverses in one batch:
- `k` field multiplications + 1 invert + `k` field multiplications
- Reduces `k` inversions to 1 inversion + `2k` multiplies

At ~7650 rows per inversion vs ~36 rows per multiply, this saves `(k-1)*(7650-36)` rows.

#### IpaFoldingChip Column Layout

Shares EccChip columns for point operations, uses NonNativeFq columns for scalar operations.

### 4.4 IpaTranscript — Fiat-Shamir in Circuit

#### Challenge Derivation

The verifier must reproduce the same challenges as the prover:
1. `theta` from `(k || all commitment points || all evaluation scalars)`
2. Each `x_i` from `(theta || L_0 || R_0 || ... || L_i || R_i)`

**But**: implementing a full transcript (absorbing 32+ points and squaring ~10 challenges) inside the circuit using Poseidon is expensive but tractable.

**Alternative**: take challenges as witnesses and verify they hash correctly.

**Recommended approach**: Challenge-witness hybrid
- Challenges `x_i` and `theta` are **witnessed** (private inputs)
- A Poseidon hash is computed over the inputs that should bind them
- The circuit constrains that `blake3(...)` or Poseidon hash matches
- This avoids in-circuit challenge derivation at the cost of making challenges "part of the proof" (which they already are — the prover picks them)

Actually, the correct approach for a recursive SNARK is to derive challenges in-circuit from a simulated transcript. But for §1.12, we can start with witnessed challenges verified by hash.

```rust
pub struct IpaTranscriptConfig {
    poseidon: PoseidonConfig<3, 2>,
    // Columns for absorbing points and scalars
    absorb: [Column<Advice>; 2],  // rate columns
    s_absorb: Selector,
}
```

**Flow**:
1. Absorb `k` (as Fp)
2. Absorb all commitment points (Pallas affine coordinates = 2 Fp each)
3. Absorb all claimed evaluations (as Fq → Fp converted)
4. Squeeze `theta` (Poseidon output → Fq via `fp_to_fq` byte rewrap)
5. For each round: absorb `L_i, R_i`, squeeze `x_i`

**Cost**: ~20 rows per absorb, ~200 rows per squeeze. For k=10: ~20·(1+2m+2k) + 200·(1+k) ≈ `40m + 2640` rows (where m = number of queries).

### 4.5 Main Circuit: IpaVerifierCircuit

```rust
pub struct IpaVerifierCircuit {
    // Public inputs
    k: u32,                    // log2(n)
    point: FqLimb,             // evaluation point (non-native Fq)
    combined_eval: FqElem,     // theta-weighted claimed eval (non-native)

    // Witness
    l_points: Vec<EcPoint>,    // k round L points
    r_points: Vec<EcPoint>,    // k round R points
    a_final: FqElem,           // final a scalar
    r_prime: FqElem,           // blinding factor

    // Constants (from params)
    g: Vec<EcPoint>,           // SRS generators (n values)
    h: EcPoint,                // blinding generator
    u: EcPoint,                // IPA challenge generator
}
```

#### Synthesis flow:

```
1. Compute b vector: b[0]=1, b[i]=b[i-1]*point  (Fq mul)
2. Fold b and G through k rounds (IpaFoldingChip)
3. Accumulate MSM terms:
   a. Add P_combined (public input point)
   b. For each round: x_i_inv * L_i + x_i * R_i
   c. (v - a*b) * U
   d. -a * G_final
   e. -r' * H
4. Full MSM evaluation: Σ s_i * P_i == 0
5. Return bit
```

**Step 4 (full MSM evaluation)** is the most challenging part. Instead of evaluating the full MSM (which requires `n+2k+4` scalar muls), we can **fold the MSM evaluation into the IPA proof itself** by using the verifier's own equation.

Wait — for the recursive verifier, we DON'T need to recompute the full MSM. The verification equation after the IPA folding is:

```
CHECK: P + Σ(x_i⁻¹·L_i + x_i·R_i) + (v−a·b)·U − a·G_final − r'·H == 0
```

This is `1 + 2k + 1 + 1 + 1 = 2k+4` scalar muls + additions. The expensive `n-1` folding of G was already done in step 2. So the final check is just `2k+4` operations.

For k=10: 24 scalar muls + additions. ~24 × 800 = **~19k rows** for the final check.

**Total estimated cost** (k=10, n=1024):

| Component | Rows |
|-----------|------|
| b vector (1023 Fq mul) | ~37k |
| G folding (1023 non-native scalar muls + 1023 point adds) | ~818k |
| Final MSM (24 scalar muls + adds) | ~19k |
| Transcript (Poseidon) | ~3k |
| L/R field ops (inversions, etc.) | ~8k |
| **Total** | **~885k rows (k=10)** |

At k=8 (n=256): ~220k rows (more practical for initial implementation).
At k=6 (n=64): ~55k rows (prototype-friendly).

---

## 5. Implementation Plan

### Phase 1 (§1.12a, ~2 weeks): NonNativeFqChip

1. Implement `FqElem` representation (3 × 85-bit limbs)
2. Implement `add`, `sub`, `mul` with range checks
3. Implement `invert` (Fermat, batched)
4. Implement `from_fp`, `to_fp_safe`
5. Write exhaustive tests for each operation

**Deliverable**: `aetheris-recursive/src/non_native_fq.rs`
- 30+ test cases covering edge cases (zero, one, carry overflow, modulus boundary)

### Phase 2 (§1.12b, ~2 weeks): NonNativeFqScalarMul

1. Implement windowed scalar mul using decomposed Fq scalar
2. Integrate with EccChip for point add/double/lookup
3. Write tests: random scalar mul roundtrip vs out-of-circuit

**Deliverable**: `aetheris-recursive/src/non_native_mul.rs`

### Phase 3 (§1.12c, ~2 weeks): IpaFoldingChip

1. Implement b vector computation (1023 Fq muls)
2. Implement G folding (1023 scalar muls + point adds)
3. Implement batch inversion for round challenges
4. Write tests: fold random values, compare with out-of-circuit

**Deliverable**: `aetheris-recursive/src/ipa_fold.rs`

### Phase 4 (§1.12d, ~2 weeks): Transcript + Integration

1. Implement in-circuit transcript using PoseidonChip
2. Wire all components into `IpaVerifierCircuit`
3. Implement the final MSM check
4. Write end-to-end test: produce IPA proof → verify in-circuit via MockProver

**Deliverable**: `aetheris-recursive/src/ipa_verifier_circuit.rs`

### Phase 5 (§1.12e, ~2 weeks): Optimization + Real Proofs

1. Benchmark with real `ParamsIPA<EpAffine>` and real proofs
2. Optimize row usage (batch operations, sharing columns)
3. Test with k=8 (n=256) and k=10 (n=1024) domain sizes
4. Validate against `verify_proof` from `aetheris-zkp`

**Deliverable**: Proving key + verifying key generation, roundtrip tests

---

## 6. Open Questions

1. **Poseidon vs blake3 for in-circuit transcript**: PoseidonChip exists but operates on Fp. Challenges need to be Fq. Option A: use Poseidon, convert output to Fq via `fp_to_fq`. Option B: implement blake3 in-circuit (very expensive). Option C: out-source challenges to witness (cheapest but requires careful soundness argument). **Decision pending: start with Poseidon.**

2. **SRS generator `g` values**: n = 2^k generators are Pallas points. At k=10, n=1024. These can be loaded as fixed-table lookups at configure time. But a table of 1024 Pallas points with 4-bit windows = 1024 × 16 = 16,384 table entries. This fits in a table column.

3. **Full MSM evaluation**: The final check `Σ s_i · P_i == 0` requires evaluating all scalar-point pairs. This is `n + 2k + 4` scalar muls. For k=10, n=1024 → 1048 scalar muls. At ~800 rows each → ~838k rows. **This dominates the circuit.** Optimization: use the MSM structure (many small scalars) to batch into smaller windows.

4. **Rejection sampling**: The verifier rejects `x_i == 0` or `x_i == 1` (verifier.rs:134–140). Probability is `2/|Fq| ≈ 2^-254`, so rejection almost never happens. The circuit can just prove it didn't happen (constant-time).

5. **Batch verification**: `AccumulatorStrategyIPA` scales each MSM by a random factor. In-circuit, this would multiply the cost by the batch size. **Decision: defer to §1.13** (recursive proof wrapper).

---

## 7. File Map

| New File | Purpose |
|----------|---------|
| `aetheris-recursive/src/non_native_fq.rs` | Fq element representation + arithmetic (add, mul, invert) |
| `aetheris-recursive/src/non_native_mul.rs` | Fq × PallasPoint scalar multiplication gadget |
| `aetheris-recursive/src/ipa_fold.rs` | IPA recursive halving circuit (fold G+b) |
| `aetheris-recursive/src/ipa_verifier_circuit.rs` | Top-level `IpaVerifierCircuit` + tests |
| `aetheris-recursive/src/lib.rs` | Add `pub mod` for new modules |

**Estimated total new code**: 1500–2500 lines (excluding tests), ~3000 lines including tests.

---

## 8. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Non-native Fq mul too expensive | Medium | High | Use 2 limbs (128-bit) instead of 3; use off-chip reduction hints |
| Circuit doesn't fit in k=11 proving key (2048 rows) | High | High | Multiple proof segments; use k=13 (8192 rows) for single proof |
| Poseidon Fiat-Shamir incompatible with verifier's blake3 transcript | Medium | Medium | Use same domain separators; verify against real transcript bytes |
| Challenge-witness hybrid weakens soundness | Low | Medium | Full in-circuit Fiat-Shamir in §1.13 wrap |

---

## 9. Out of Scope

- **Full recursive SNARK wrapper** (§1.13): wraps accumulator chain in a constant-size proof
- **Batch verification**: multiple proofs simultaneously
- **Multi-open beyond one point**: the verifier handles multiple evaluation points; this doc focuses on one
- **State root integration** (§1.14)
- **Soft fork activation** (§1.15)
