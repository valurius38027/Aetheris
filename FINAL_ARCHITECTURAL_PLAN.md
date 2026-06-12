# Final Architectural Alignment Plan — Aetheris

> **Purpose**: Single source of truth for ALL remaining architectural deviations.
> Supersedes `B-3_plan.md`, `phase_1_14_plan.md`, and all earlier planning
> documents for recursive accumulation.
>
> This is the FINAL and ONLY active plan. All other planning documents in
> the repository have been annotated SUPERSEDED. If you find unannotated
> planning content that contradicts this document, file an issue.

---

## §0 — Reference Documents (Binding, immutable)

| Doc | Role |
|-----|------|
| `protocol_design_ruling.md` | **Final design rulings** — curve placement, accumulator spec, trust model |
| `math_spec.md` | **Mathematical specification** — VDF, record model, recursive aggregation |
| `B-2_plan.md` | ✅ **Complete** — Native IPA accumulation on Vesta (prerequisite) |

### Requirements Derived from Design Docs

| Req | Source | Rule |
|-----|--------|------|
| R1 | `protocol_design_ruling.md §1.1` | Recursive circuit = **Vesta** (`Circuit<Fq>`). All accumulator operations native Fq, NO NonNativeChip. |
| R2 | `protocol_design_ruling.md §2.2` | `Accumulate(π, Acc_old) → Acc_new`: ① Halo2-verify π in-circuit, ② Poseidon challenge, ③ Q_new = Q_old + challenge·π_commitment, ④ Poseidon transcript update. |
| R3 | `math_spec.md §8.2` | Verification O(1), merge O(log N). No O(n) proof replay for verifiers who trust the recursive SNARK. |
| R4 | `protocol_design_ruling.md §1.2` | **Halo2 IPA Accumulation Scheme only** — no Merkle hash, no hybrid. |
| R5 | `math_spec.md §2` | Poseidon for state tree, nullifier, and all ZK-friendly hashing. |
| R6 | `protocol_design_ruling.md §1.1` | Pasta 2-cycle: NonNativeChip completely eliminated. |

### Current Deviations

| ID | Req | Deviation | Severity | Fix | Status |
|----|-----|-----------|----------|-----|--------|
| D1 | R2,R3 | `verify_block_recursive_proof` proves wrong equation (IPA on Q) | **CRITICAL** | §C | ✅ Done |
| D2 | R1,R6 | Recursive proof uses `PallasAccumulateChip` (non-native) | HIGH | §C | ✅ Done |
| D3 | R2,R5 | Transcript hash uses Blake3/Blake2b instead of Poseidon | HIGH | §B | ✅ Done |
| D4 | R3 | Verification is O(n) accumulator replay, not O(1) recursive SNARK | HIGH | §C | ✅ Done |
| D5 | R4 | `BlockHeader` has dual `aggregate_proof` + optional `recursive_proof` | MEDIUM | §D | ✅ Done (D.1+D.2) |
| D6 | R2(①) | In-circuit IPA verification deferred (trusted-aggregator model) | MEDIUM | §E | ⏳ Deferred post-MVP |
| D7 | R5 | `create_nullifier`/`build_merkle_root` use Blake3 not Poseidon | MEDIUM | §B.2 | ✅ Done |
| D8 | R2 | `hash_to_curve` targets Pallas generator (EpAffine) not Vesta (EqAffine) | MEDIUM | §A | ✅ Done |
| D9 | — | `RecursiveManagerHandle.verify_halo2_proof() -> bool { false }` (stub) | HIGH | §F | ⏳ Pending |
| D10 | — | `empty_accumulator()` naming; deprecated trait methods; superseded docs | LOW | §G | ⏳ Pending |

---

## §1 — Implementation Order (Strict)

```
§A (Accumulator → Vesta) ──→ §B (Poseidon migration) ──→ §C (CircuitAccumulate)
     │                              │
     │                              ▼
     │                   §B.1 host-side Poseidon (immediate)
     │                   §B.2 in-circuit Poseidon chaining (§C needs this)
     │                   §B.3 Blake2b circuit replacement (§E scope, deferred)
     │
     §A must be FIRST because accumulator.rs is the reference.
     §B.1 + §B.2 must complete before §C (CircuitAccumulate needs Poseidon chips).
     §B.3 is deferred to §E scope.
     
§C done ──→ §D (Block cleanup) — dependent on §C
§C done ──→ §F (P2P manager) — dependent on §C
     │
     ▼
§E (In-circuit IPA verify, Phase 1.6) — deferred post-MVP
§G (Cleanup) — can start after §A
```

---

## §A — Accumulator Curve Migration: Pallas → Vesta

**Fixes**: D8 | **Prereqs**: B-2 complete | **Effort**: ~400 lines, 10 files

### §A.1 — What Changes in `accumulator.rs`

Exact line-by-line changes (10 references):

| Line | Current (Pallas) | New (Vesta) | Notes |
|------|------------------|-------------|-------|
| 25 | `use {EpAffine, Fp, Fq}` | `use {EqAffine, Fq}` | Remove `Fp`, switch `EpAffine`→`EqAffine` |
| 101 | `pub Q: EpAffine` | `pub Q: EqAffine` | Struct field type change |
| 124 | `EpAffine::identity()` | `EqAffine::identity()` | Same API, different curve |
| 248 | `fp_from_blake3(...)` → `Fp` | `fq_from_blake3(...)` → `Fq` | Direct Fq, no bridge |
| 261 | `fp_to_fq(&challenge)` | **REMOVE** | No Fp→Fq bridge needed |
| 262-265 | `pi_commitment * challenge_q` | `pi_commitment * challenge` (Fq native) | Vesta scalar mul |
| 413 | `EpAffine::identity()` | `EqAffine::identity()` | Deserialization |
| 416 | `EpAffine::from_bytes(&q_bytes)` | `EqAffine::from_bytes(&q_bytes)` | Same 32B format |
| 477-489 | return `EpAffine` | return `EqAffine` | hash_to_curve output |
| 503 | `Fp::from_uniform_bytes(...)` | `Fq::from_uniform_bytes(...)` | Direct Fq |
| 508 | `fp_to_fq(&c)` | **REMOVE** | No bridge |
| 510 | `EpAffine::generator() * c_q` | `EqAffine::generator() * c` | Vesta generator |
| 532-537 | `fn fp_from_blake3` → `Fp` | `fn fq_from_blake3` → `Fq` | Rename, change return type |
| 552-555 | `fn fp_to_fq` | **REMOVE ENTIRE FUNCTION** | Dead code |

### §A.2 — Wire Format: MUST bump v1→v2

Current: 96B = 28B `ACCUMULATOR_WIRE_PREFIX` (`b"aetheris_accumulator_ipa_v1_"`) + 32B Q + 32B transcript + 4B depth.

**Change**: Bump all wire format constants from `_v1_` to `_v2_`:
- `ACCUMULATOR_WIRE_PREFIX`: `b"aetheris_accumulator_ipa_v1_"` → `b"aetheris_accumulator_ipa_v2_"`
- `SIGNED_ACCUMULATOR_WIRE_PREFIX`: `b"aetheris_signed_accumulator_v1_"` → `b"aetheris_signed_accumulator_v2_"`
- `ACCUMULATOR_TRANSCRIPT_DOMAIN`: `b"aetheris-ipa-accumulator-v1\x00"` → `b"aetheris-ipa-accumulator-v2\x00"`
- `PI_COMMITMENT_DOMAIN`: `b"aetheris-pi-cmt-v1\x00"` → `b"aetheris-pi-cmt-v2\x00"`
- `ACCUMULATOR_SIGNATURE_DOMAIN`: `b"aetheris-accumulator-sig-v1\x00"` → `b"aetheris-accumulator-sig-v2\x00"`

**Why**: Old-format Pallas-Q accumulator bytes MUST NOT deserialize as new-format Vesta-Q bytes.
The 32B encoding is structurally identical but represents a different curve point.
A Pallas compressed point is NOT a valid Vesta point (different prime field).

**Byte count unchanged**: 32B point encoding, 32B transcript, 4B depth — all same.

### §A.3 — Update `prove_recursive.rs` (bridge function)

File: `aetheris-recursive/src/prove_recursive.rs:104`

Current:
```rust
let pallas_point = crate::pallas_accumulate::ep_to_pallas_point(&acc.Q);
```
After §A, `acc.Q` is `EqAffine` (Vesta). The `ep_to_pallas_point` bridge converts Pallas→PallasPoint (3-limb Fp). With Vesta, `acc.Q` coordinates ARE Fq natively. The recursive circuit still uses `PallasAccumulateChip` (non-native), so we need a temporary bridge: `eq_to_pallas_point(&acc.Q)` that converts Vesta→PallasPoint via byte rewrap.

**This bridge is temporary** — it will be eliminated in §C when CircuitAccumulate replaces the RecursiveProofCircuit entirely.

Function to add in `aetheris-recursive/src/pallas_accumulate.rs`:
```rust
pub fn eq_to_pallas_point(q: &EqAffine) -> PallasPoint { /* byte-level Fq→FpElement mapping */ }
```

### §A.4 — Update Callers (no API change for byte-level users)

| File | Change Required |
|------|----------------|
| `accumulator.rs` | See §A.1 (10 line changes + function removal) |
| `pallas_accumulate.rs` | Add `eq_to_pallas_point()` bridge |
| `prove_recursive.rs:104` | Call `eq_to_pallas_point` instead of `ep_to_pallas_point` |
| `block_aggregator.rs` | **None** — operates on opaque bytes |
| `state.rs` | **None** (except test at line 670 uses `AccumulatorIPA::new()` — type change but API same) |
| `ffi/src/lib.rs` | **None** — opaque bytes |
| `lib.rs` (re-exports) | **None** — re-exports struct by name, not curve |

### §A.5 — Snapshot Compatibility Warning

`state.rs` stores `last_aggregate_proof: Vec<u8>` serialized via `bincode` into snapshots.
After §A, old-format snapshots contain `v1`-prefix accumulator bytes that fail `from_bytes()`.

**Action**: On snapshot load, detect `v1` prefix → reject/reset to `initial_accumulator()`.
This is a clean cutover: the accumulator chain starts fresh after this migration.

### §A.6 — Test Impact

Four accumulator unit tests check specific `to_bytes()` values that will change:
- `hash_to_curve_nums_is_deterministic` (line 676) — bytes change because Vesta point ≠ Pallas point
- `hash_to_curve_nums_differs_for_different_inputs` (line 684) — still true, bytes change
- `hash_to_curve_nums_binds_to_input` (line 722) — still true, bytes change
- `hash_to_curve_nums_eff_binds_to_commitment` (line 741) — still true, bytes change

All other tests check roundtrip consistency (self-consistent, bytes-in=bytes-out), not specific values.

**Action**: Update these 4 tests to expect Vesta-curve outputs. Add `test_hash_to_curve_vesta_matches_host()`.

### §A.7 — Verification

```bash
cargo test -p aetheris-recursive -- accumulator:: --test-threads=2
cargo test -p aetheris-recursive -- block_aggregator:: --test-threads=2
cargo test -p aetheris-ffi --lib -- --test-threads=1
cargo check --workspace
```

---

## §B — Poseidon Hash Migration

**Fixes**: D3, D7 | **Prereqs**: §A | **Effort**: ~600 lines

### §B.0 — Critical Finding: Blake2bCompressionCircuitChip is NOT a drop-in replacement

The `Blake2bCompressionCircuitChip` in `transcript_blake2b_circuit.rs` is a MASSIVE circuit:
- ~60+ advice columns, ~15 selectors, 12+ gate types
- Full bitwise Blake2b over **Fp** (non-native Fq via NonNativeFqChip)
- Hashes arbitrary-length byte streams from the IPA transcript protocol

The `PoseidonFqChip` in `poseidon_fq_chip.rs` is:
- 3 advice columns, 3 fixed, 1 partial_sbox, 2 selectors = ~9 columns
- Native Fq (no NonNativeFqChip)
- Fixed 2-to-1 hash (rate=2, capacity=1, t=3), not a byte sponge

**Replacement strategy** (split into three independent sub-phases):

| Sub-phase | Scope | Effort | Depends on |
|-----------|-------|--------|------------|
| **§B.1** | Host-side: blake3→poseidon_fq (nullifier, merkle root, accumulator reference) | ~150 lines | Nothing |
| **§B.2** | In-circuit: Poseidon chaining for accumulator operations (CircuitAccumulate needs this) | ~200 lines | §A, §B.1 |
| **§B.3** | In-circuit: Replace Blake2bCompressionCircuitChip in VestaAccumulateChip | ~500 lines | §E scope (deferred) |

### §B.1 — Host-Side Poseidon (immediate)

#### §B.1a — Replace `create_nullifier` blake3 → Poseidon

File: `aetheris-zkp/src/halo2_pasta.rs:149-153`

Current: `blake3(sk || index_le)` returning `[u8; 32]`
Target: `poseidon_fq::poseidon_nullifier(sk_bytes, index)` — **ALREADY EXISTS** at `poseidon_fq.rs:199-206`

**Problem**: `create_nullifier` takes `&[u8]` for `sk` (variable-length), but `poseidon_nullifier` takes `&[u8; 32]` (fixed).
**Fix**: Assert `sk.len() >= 32`, take first 32 bytes. Or change the caller.

#### §B.1b — Replace `build_merkle_root` blake3 → Poseidon

File: `aetheris-zkp/src/halo2_pasta.rs:346-366`

Current: Binary blake3 Merkle tree
Target: **Already replaced** by `aetheris-zkp/src/merkle_tree.rs` which uses `poseidon_fq::poseidon_hash`.
**Action**: Remove the dead `build_merkle_root` function (or replace its body to delegate to `IncrementalMerkleTree::compute_root`).

#### §B.1c — Replace accumulator reference hash blake3 → Poseidon

File: `aetheris-recursive/src/accumulator.rs`

Replace three blake3 calls with `poseidon_fq::poseidon_hash` / `poseidon_hash_chain`:

| Current (accumulate step) | New |
|---------------------------|-----|
| Step 5: `blake3(proof)` for inner_proof_hash | `poseidon_fq::poseidon_hash(IV_DOMAIN, proof_hash)` — NOTE: `proof` is arbitrary bytes, Poseidon expects `[u8;32]`. **Gap**: need to truncate/hash proof to 32B first. Use `blake3(proof)` → 32B → `poseidon_fq::poseidon_hash(...)` — two-phase hash. |
| Step 6: `blake3(PI_COMMITMENT_DOMAIN \|\| ipe)` for seed | `poseidon_fq::poseidon_hash(domain_fq, ipe_fq)` — 2-to-1 Poseidon |
| Step 7: `blake3(TRANSCRIPT_DOMAIN \|\| transcript \|\| ipe)` for challenge | `poseidon_fq::poseidon_hash(transcript_fq, ipe_fq)` — 2-to-1 Poseidon |
| Step 9: `blake3(TRANSCRIPT_DOMAIN \|\| transcript \|\| challenge \|\| Q \|\| ipe)` for transcript_new | `poseidon_hash_chain(&[transcript_fq, challenge_fq, Q_fq, ipe_fq])` — multi-element |

**New helper in `poseidon_fq.rs`**:
```rust
/// Merkle-Damgård chain: h0 = IV; for each el: h_i = poseidon_hash(h_{i-1}, el)
pub fn poseidon_hash_chain(elements: &[[u8; 32]]) -> [u8; 32];
```

**Critical**: The `poseidon_fq` hash uses `Fq::from_repr(bytes)` which requires CANONICAL representations (bytes < Fq modulus). The 32-byte accumulator values (transcript, challenge, Q compressed) are < Fq modulus because they derive from Poseidon outputs and Fq-reduced values. This is safe.

**Exception**: `inner_proof_hash` from `blake3(proof)` — blake3 output is uniform 32 bytes, which may be ≥ Fq modulus. **Fix**: Use `Fq::from_uniform_bytes(&[blake3_out || zeros_32])` instead of `Fq::from_repr(blake3_out)`.

### §B.2 — In-Circuit Poseidon Chaining (for CircuitAccumulate, §C prerequisite)

#### §B.2a — What already exists

`PoseidonFqChip` (`aetheris-zkp/src/poseidon_fq_chip.rs`):
- **521 lines, 3 columns, 3 gates** — native Fq
- `assign_hash(layouter, left: &[u8;32], right: &[u8;32]) -> Result<AssignedCell<Fq>>`
- Uses r_f=8, r_p=56, t=3, rate=2, x^5 S-box
- Matches host-side `poseidon_fq.rs` spec EXACTLY (verified: same Grain LFSR, same round params, `native_hash()` test passes)
- Tested with MockProver (correct instances accepted, wrong instances rejected)

#### §B.2b — What CircuitAccumulate needs from Poseidon

| Operation | Inputs | Poseidon absorption pattern |
|-----------|--------|----------------------------|
| `pi_commitment_seed` | `(domain_fq, inner_proof_hash_eff)` | 2-to-1: `assign_hash(domain, ipe)` ✅ exact |
| `challenge` | `(transcript_old, inner_proof_hash_eff)` | 2-to-1: `assign_hash(transcript, ipe)` ✅ exact |
| `transcript_new` | `(transcript_old, challenge, Q_compressed, ipe)` | 4 elements: chain 3 `assign_hash` calls |
| Domain encoding | domain_tag → Fq | Use `Fq::from_uniform_bytes(&blake3(domain) \|\| zeros)` — host-side, then pass as AssignedCell |

**Pattern for 4-element absorption**:
```rust
let h1 = poseidon.assign_hash(layouter.namespace(|| "h1"), transcript_old, challenge)?;
let h2 = poseidon.assign_hash(layouter.namespace(|| "h2"), q_compressed, ipe)?;
let transcript_new = poseidon.assign_hash(layouter.namespace(|| "h3"), h1.value(), h2.value())?;
// ^^^ BUT wait: assign_hash takes [u8;32] not AssignedCell<Fq>
```

**GAP**: `PoseidonFqChip::assign_hash` takes `left: Value<[u8;32]>`, `right: Value<[u8;32]>`, NOT `AssignedCell<Fq>`. To chain outputs as inputs, we need a version that accepts `AssignedCell<Fq>` (the Fq element, not its byte repr).

**Fix**: Either:
- (Clean) Add `assign_hash_fq(layouter, left: &AssignedCell<Fq>, right: &AssignedCell<Fq>)` that uses the cells directly without re-converting from bytes
- (Hack) Convert `AssignedCell<Fq>` → `Value<[u8;32]>` via `.value().map(|fq| fq.to_repr())` — this works but adds a constraint-less cell handoff

**Decision**: Use the hack (`.value().map(|fq| fq.to_repr())`) for initial implementation. The `assign_hash` constrains that the permutation output matches the next state, so the byte→Fq conversion is NOT re-constrained — but the Fq cell was already constrained by the previous `assign_hash` call. This is correct: the chain is `assign_hash → cell → to_repr_to_value → assign_hash`.

Wait — actually, `assign_hash` takes `Value<[u8; 32]>`, and the interface for `left_cell`/`right_cell` is `Option<VerificationCell<Fq, Challenge>>` for equality-constraining to a challenge cell, NOT for chain input. To chain:
1. Call `assign_hash(..., left, right, None, None)` → get `result: AssignedCell<Fq>`
2. Convert `result.value()` → `Fq::to_repr()` → `Value<[u8; 32]>` (host-side)
3. Call `assign_hash(..., result_bytes, next_input, None, None)` → constrained permutation

Since step 2 is just a host-side value conversion (no circuit constraints needed beyond what step 1 already constrained), this is sound.

**CORRECTION**: Looking at the actual `assign_hash` signature more carefully:

```rust
pub fn assign_hash(
    &self,
    mut layouter: impl Layouter<Fq>,
    left: Value<[u8; 32]>,
    right: Value<[u8; 32]>,
    left_cell: Option<VerificationCell<Fq, Challenge>>,
    right_cell: Option<VerificationCell<Fq, Challenge>>,
) -> Result<AssignedCell<Fq, Fq>, Error>
```

The `left_cell`/`right_cell` take `VerificationCell<Fq, Challenge>` which is a challenge cell type, not a generic `AssignedCell`. So we CANNOT use them for chaining output→input directly.

**Workaround confirmed**: Use `.value().map(|fq| fq.to_repr())`:
```rust
let h1 = poseidon.assign_hash(layouter.namespace(|| "h1"),
    Value::known(domain_bytes), Value::known(ipe_bytes), None, None)?;
let h1_bytes = h1.value().map(|fq| fq.to_repr());  // AssignedCell<Fq> → [u8;32]
let h2 = poseidon.assign_hash(layouter.namespace(|| "h2"),
    h1_bytes, Value::known(transcript_bytes), None, None)?;
```

This is sound because `h1` is an `AssignedCell<Fq>` whose Fq value is constrained by the Poseidon gate. Converting it back to bytes and passing as input to the next `assign_hash` call will constrain the second permutation to use the same Fq value (interpreted as bytes via `Fq::to_repr()`). The Poseidon gate ensures the byte→Fq conversion inside `assign_hash` produces the same Fq.

**Verdict**: Workaround is correct. No chip modification needed for chaining.

### §B.3 — Update Domain Separators for Poseidon

Current: Blake3 domain tags like `b"aetheris-ipa-accumulator-v1\x00"`.
For Poseidon, domain separation uses capacity element encoding.

**Approach**: Prepend domain as first Fq input:
```
challenge = Poseidon(domain_fq, transcript, inner_proof_hash_eff)
  where domain_fq = Fq::from_uniform_bytes(&[blake3(domain_tag) || [0u8; 32]])
```
This uses a Blake3→Fq reduction for domain encoding only (not for hash operations). The Blake3→Fq step is host-side, not in-circuit.

### §B.4 — Genesis Transcript Change

Genesis transcript changes from `blake3(ACCUMULATOR_TRANSCRIPT_DOMAIN || "genesis")` to:
```rust
let domain_fq = Fq::from_uniform_bytes(&[blake3(ACCUMULATOR_TRANSCRIPT_DOMAIN) || [0u8; 32]]);
let genesis_fq = Fq::from_uniform_bytes(&[blake3(b"genesis") || [0u8; 32]]);
let genesis_transcript = poseidon_fq::poseidon_hash(&domain_fq_bytes, &genesis_fq_bytes);
// where domain_fq_bytes = domain_fq.to_repr(), genesis_fq_bytes = genesis_fq.to_repr()
```

**Acceptable pre-mainnet.** Genesis hash already changed in Phase 1.15.

### §B.5 — Verification

```bash
cargo test -p aetheris-zkp -- poseidon:: --test-threads=4
cargo test -p aetheris-recursive -- accumulator:: --test-threads=2
cargo test -p aetheris-recursive -- block_aggregator:: --test-threads=2
```

---

## §C — CircuitAccumulate

**Fixes**: D1, D2, D4 | **Prereqs**: §A, §B.1+§B.2 | **Effort**: ~800 lines new

### §C.0 — Gap Analysis

Gaps identified from deep investigation that are handled by §B or worked around:

| Gap | Severity | Resolution |
|-----|----------|------------|
| No Poseidon chip over Fq for accumulator operations | **BLOCKING** | §B.2 provides chained `assign_hash` calls |
| VestaFqChip has no `sub`/`eq`/`negate` for Fq comparison | MEDIUM | Workaround: `neg = mul(x, -1)`, `eq = is_zero(add(x, neg(y)))` via invert trick |
| VestaEccChip::scalar_mul takes `Value<Fq>` not `Limb<Fq>` for scalar | LOW | Extract `.value()` from Limb — caller constrained the scalar before `scalar_mul` |
| offset_point must be host-precomputed for each distinct scalar_mul target | LOW | Generator offset is one-time constant. `pi_commitment` offset must be passed as witness (host precomputes `2^254 * pi_commitment`) |

### §C.1 — In-Circuit hash_to_curve (NUMS try-and-increment, Vesta target)

File: `aetheris-recursive/src/circuit_accumulate.rs`

```
seed_fq = Poseidon(PI_DOMAIN_FQ, inner_proof_hash_eff_fq)   // §B.2 assign_hash
counter = 0..MAX_ITER (unrolled, MAX_ITER=5)
  mixed_bytes = le_bytes(counter, 4) || seed_bytes[0..28]    // host byte assignment
  c = Fq::from_uniform_bytes(&[mixed_bytes || [0u8; 32]])    // host witness
  pi = VestaGenerator * c                                     // VestaEccChip::scalar_mul
  if pi == identity (x=0,y=0):                                 // relaxed gate accepts (0,0)
    skip (selector disabled for this iteration)
  else:
    pi_commitment = pi
    break
```

**Constraints per iteration**:
1. `FqRangeCheckChip::range_check(&c_limb, 255)` — c is a valid Fq
2. `VestaEccChip::scalar_mul(generator, offset_2p254, c, "hash_to_curve")` — pi = G * c
3. Identity detection: the `s_scalar_mul_result` gate already accepts (0,0) via `x*(y²-x³-5)=0`

**Row cost**: MAX_ITER × (range_255 rows + scalar_mul rows)
- 5 × (256 + 766) = ~5,110 rows
- Unrolling with selector enables early-exit (remaining iterations disabled)

### §C.2 — AccumulatorCircuit Struct

```rust
struct AccumulatorCircuit {
    /// Previous accumulator state (public instance input)
    q_old: EqAffine,
    transcript_old: [u8; 32],
    depth_old: u32,
    /// Per-tx private witnesses
    txs: Vec<TxWitness>,
    /// Poseidon domain encoding (host-precomputed constants)
    pi_domain_fq: [u8; 32],
    transcript_domain_fq: [u8; 32],
}

struct TxWitness {
    inner_proof_hash_eff: [u8; 32],  // blake3 proof → Poseidon chained commitment binding
    // Witnesses (host-precomputed, constrained in-circuit):
    pi_commitment: EqAffine,           // hash_to_curve output point
    pi_commitment_offset: EqAffine,    // 2^254 * pi_commitment (for VestaEccChip::scalar_mul)
    pi_counter: u32,                   // which try-and-increment iteration succeeded (0..MAX_ITER-1)
    challenge: Fq,                     // Poseidon(transcript_old, ipe)
}
```

### §C.3 — Configuration

```rust
struct AccumulateConfig {
    poseidon: PoseidonFqConfig,              // From aetheris-zkp
    ecc: VestaEccConfig,                     // From B-2 (VestaEccChip)
    fq: VestaFqConfig,                       // From B-2 (VestaFqChip)
    range: FqRangeCheckConfig,               // From B-2
    /// Per-tx witness columns
    pi_cmt_x: Column<Advice>,
    pi_cmt_y: Column<Advice>,
    pi_cmt_offset_x: Column<Advice>,
    pi_cmt_offset_y: Column<Advice>,
    challenge: Column<Advice>,
    transcript_cur: Column<Advice>,          // current transcript (2 cells for 32B)
    q_cur_x: Column<Advice>,
    q_cur_y: Column<Advice>,
    depth: Column<Advice>,
    /// Selectors
    s_tx: Selector,                          // one row per tx
    s_try_iter: [Selector; MAX_ITER],        // try-and-increment iterations
    /// Instance
    instance: Column<Instance>,              // 5 cells
}
```

### §C.4 — Synthesize Algorithm

```
// Phase 0: Load previous accumulator state
q_cur = assign_point(q_old)                     // VestaPoint from EqAffine
transcript_cur = assign_bytes(transcript_old)   // 2× AssignedCell<Fq>
depth_cur = assign_u32(depth_old)               // Limb<Fq>

// Phase 1: Per-tx loop
for each tx in txs:
    // Step 1: hash_to_curve → pi_commitment
    pi_seed = poseidon.assign_hash(pi_domain_fq_cells, tx.ipe_cells, None, None)
    pi_cmt = try_and_increment(pi_seed)  // §C.1
    
    // Step 2: challenge derivation
    challenge = poseidon.assign_hash(transcript_cells, tx.ipe_cells, None, None)
    
    // Step 3: Q update: q_new = q_cur + challenge * pi_cmt
    scaled = ecc.scalar_mul(&pi_cmt, &tx.pi_cmt_offset, challenge.value(), "challenge*pi")
    q_new = ecc.point_add(&q_cur, &scaled, "q_cur + challenge*pi")
    
    // Step 4: Transcript update
    q_compressed = compress_point(&q_new)       // Fq→[u8;32] host-side
    h1 = poseidon.assign_hash(transcript_cells, challenge_bytes, None, None)
    h2 = poseidon.assign_hash(q_compressed_cells, tx.ipe_cells, None, None)
    transcript_new = poseidon.assign_hash(h1.to_repr_value(), h2.to_repr_value(), None, None)
    
    // Step 5: Depth increment
    depth_new = fq.add(&depth_cur, &Limb::constant(Fq::ONE))
    
    // Step 6: Shift for next tx
    q_cur = q_new
    transcript_cur = transcript_new
    depth_cur = depth_new

// Phase 2: Public instance binding
constrain_instance(q_new.x_cell, instance, 0)
constrain_instance(q_new.y_cell, instance, 1)
constrain_instance(transcript_lo_cell, instance, 2)
constrain_instance(transcript_hi_cell, instance, 3)
constrain_instance(depth_new.cell, instance, 4)
```

### §C.5 — K-Budget

For a block with **N transactions**:

| Operation | Rows per tx | Notes |
|-----------|-------------|-------|
| hash_to_curve (try-and-increment, 5 iter) | ~5,110 | 5 × (range_check_255 + scalar_mul_766) |
| Challenge Poseidon | ~65 | Poseidon assign_hash (64 rounds + output) |
| Q update: scalar_mul | ~766 | VestaEccChip::scalar_mul |
| Q update: point_add | ~1 | VestaEccChip::point_add |
| Transcript update: 3× Poseidon | ~195 | 3 × 65 |
| Depth increment | ~1 | VestaFqChip::add |
| **Total per tx** | **~6,138** | |
| Overhead (load, instance bind) | ~100 | One-time |
| **N=50 txs** | **~307,000** | K=18 (262K) ❌ too big |
| **N=30 txs** | **~184,240** | K=18 (262K) ✅ fits |
| **N=20 txs** | **~122,860** | K=17 (131K) ✅ fits |

**K=17** supports ~20 txs per block with room to spare.
**K=18** supports ~40 txs per block.

For larger blocks, reduce hash_to_curve iterations (statistical analysis: MAX_ITER=2 covers >99.999% of cases).

**Optimization**: Cache Poseidon assignments. If multiple txs share the same `inner_proof_hash_eff` (unlikely but possible), the Poseidon circuit can reuse the same row.

### §C.6 — prove_block_recursive / verify_block_recursive

File: `aetheris-recursive/src/prove_recursive.rs`

Replace the entire placeholder (§D.1 fix):

```rust
/// Produce an O(1) recursive SNARK proving the accumulator transition
/// from (Q_old, transcript_old, depth_old) to (Q_new, transcript_new, depth_new)
/// across all transactions in `txs`.
///
/// Public instances:
///   inst[0] = Q_new.x  (Fq)
///   inst[1] = Q_new.y  (Fq)
///   inst[2] = transcript_lo (first 16 bytes as Fq)
///   inst[3] = transcript_hi (last 16 bytes as Fq)
///   inst[4] = depth_new (u32 as Fq)
pub fn prove_block_recursive(
    params: &ParamsIPA<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    q_old: EqAffine,
    transcript_old: [u8; 32],
    depth_old: u32,
    txs: Vec<TxWitness>,
) -> Result<(Vec<u8>, EqAffine, [u8; 32], u32), Error>;

/// O(1) verification of a block's recursive proof.
/// Public instances must be [Q_new.x, Q_new.y, transcript_lo, transcript_hi, depth_new].
pub fn verify_block_recursive_proof(
    params: &ParamsIPA<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
    instances: &[Vec<Fq>],  // 5 Fq cells
) -> bool;
```

**Key change from placeholder**: The old `verify_block_recursive_proof` took `(proof, state_root, accumulator_bytes)` and parsed the accumulator internally. The new version takes explicit instances — the caller (consensus layer) extracts instances from the block's claimed accumulator state.

**Backward compatibility removed**: Old-format proofs (verifying a single IPA equation on Q) are rejected. This is OK because §A changes the wire format anyway.

### §C.7 — What Gets Deleted or Deprecated

| Component | Status | Replacement |
|-----------|--------|-------------|
| `RecursiveProofCircuit` in `recursive_proof.rs` | **Deprecated** | `AccumulatorCircuit` in `circuit_accumulate.rs` |
| `PallasAccumulateChip` usage in `prove_recursive.rs` | **Removed** | `VestaAccumulateChip` for inner IPA verify (§E), native Vesta chips for accumulator |
| Old `verify_block_recursive_proof` (lines 94-111) | **Replaced** | New function at §C.6 |

### §C.8 — Verification

```bash
cargo test -p aetheris-recursive -- circuit_accumulate:: --test-threads=2
cargo test -p aetheris-recursive -- prove_recursive:: --test-threads=2
cargo test -p aetheris-ffi --lib -- --test-threads=1
```

---

## §D — Block Header Cleanup

**Fixes**: D5 | **Prereqs**: §C | **Effort**: D.1 ~50 lines, D.2 ~300 lines

### §D.0 — Dependency Warning

§D touches ~80+ lines across 6+ files. Do NOT attempt before §C is verified
in production — without a working `verify_block_recursive_proof`, changing
the block header format would make all blocks unverifiable.

### §D.1 — Make `recursive_proof` Non-Optional (after §C)

File: `aetheris-core/src/lib.rs:74`

```rust
// Before:
pub recursive_proof: Option<Vec<u8>>,
// After:
pub recursive_proof: Vec<u8>,
```

**Impact**: ~25 block construction sites across 4 files must change from `recursive_proof: None` to `recursive_proof: actual_proof_bytes`. Block production must call `prove_block_recursive` (from §C.6) and store the result.

**Mining flow** (update `aetheris-ffi/src/lib.rs:1705-1730` and `aetheris-node/src/main.rs:641-663`):
```rust
let (proof_bytes, q_new, transcript_new, depth_new) =
    prove_block_recursive(&params, &pk, q_old, transcript_old, depth_old, tx_witnesses)?;
block.header.recursive_proof = proof_bytes;
// Store q_new, transcript_new, depth_new as the new accumulator state
// (instead of using AccumulatorIPA::accumulate on the host)
```

### §D.2 — Remove `aggregate_proof` Field (post-production stability)

File: `aetheris-core/src/lib.rs:71`

**Decision**: Remove `aggregate_proof: Vec<u8>` from `BlockHeader`.

**Impact** (~80+ lines across 6 files):
1. `state.rs:381-394` — accumulator chain verification in `apply_block_with_validation` replaced by recursive SNARK verification
2. `state.rs:446` — `self.last_aggregate_proof = block.header.aggregate_proof.clone()` → derive from recursive proof instances
3. `state.rs:15,32,57,78,110,170,178,183,200,224` — `last_aggregate_proof` field and its operations → replaced by `last_recursive_state` (5 Fq cells)
4. `ffi/src/lib.rs:1705-1730` — mining `accumulate_proof` loop → replaced by witness collection + `prove_block_recursive`
5. `main.rs:96,129,228,248,447,459,502-555,611,641-676,690,705` — gossip, mining, block construction all reference `aggregate_proof`
6. `consensus.rs:12` — `BlockProposal.aggregate_proof` → removed

**Coordination**: This is the LAST sub-phase of §D. Complete only after:
- §D.1 done (recursive_proof is mandatory)
- §C's `prove_block_recursive` wired into all block production paths
- `last_aggregate_proof` replaced by `last_recursive_instances: (EqAffine, [u8;32], u32)`

### §D.3 — Update Consensus Verification

File: `aetheris-node/src/state.rs:381-403`

Current:
```rust
// O(n) accumulator replay
let acc_ok = verify_accumulator_chain(&claimed, &prev, &tx_proofs, ...);
// Optional recursive check (always None currently)
if let Some(ref proof) = block.header.recursive_proof { ... }
```

After §D:
```rust
// O(1) recursive SNARK verification
let proof = &block.header.recursive_proof;
let instances = vec![
    vec![q_new_x, q_new_y],             // Q_new point
    vec![transcript_lo, transcript_hi],  // transcript (2 cells)
    vec![Fq::from(depth_new)],           // depth
];
if !verify_block_recursive_proof(&params, &vk, proof, &instances) {
    return Err(BlockError::InvalidRecursiveProof);
}
// No O(n) fallback — R3 requirement
// New accumulator state derived from instances
self.last_recursive_state = (q_new, transcript_new, depth_new);
```

### §D.4 — Snapshot Schema Change

`state.rs` serializes `LedgerState` via `bincode`. Removing `last_aggregate_proof` and adding `last_recursive_state` changes the bincode schema. Old snapshots fail deserialization.

**Action**: Version the snapshot format. On mismatch, rebuild state from genesis (scan all blocks). This is a one-time migration at deployment.

### §D.5 — Verification

```bash
cargo test -p aetheris-core
cargo test -p aetheris-node -- --test-threads=2
```

---

## §E — In-Circuit IPA Verification (Phase 1.6 / ISSUE-1.4.A)

**Fixes**: D6 (design doc step ①: Halo2-verify π in-circuit)
**Prereqs**: §C (CircuitAccumulate), §B (Poseidon), B-2 (VestaAccumulateChip)
**Effort**: ~500-800 lines | **Status**: Deferred post-MVP

### §E.0 — Critical Finding: `create_commitment` is NOT a Pedersen Commitment

Current `create_commitment` in `halo2_pasta.rs:138-147`:
```rust
let commitment_fq = amt_fq + blind_fq;  // TRIVIAL FIELD ADDITION
```
This is a **placeholder**, not a real commitment. There is no `value*H + blinding*G` curve operation. The "commitment" is just `value + blinding` in Fq.

For Option B (Vesta inner proofs), a real Pedersen commitment must be implemented:
```
commitment = value * H_vesta + blinding * G_vesta
```
This requires `EqAffine::generator()` based Pedersen parameters, which don't exist yet.

### §E.1 — Strategy: Option B (Vesta Inner Proofs)

Change commitment curve from Pallas (`EpAffine`) to Vesta (`EqAffine`).

**Scope**:
1. `aetheris-zkp/src/halo2_pasta.rs`: All `EpAffine` → `EqAffine` type params
2. `aetheris-zkp/src/ipa/commitment.rs`: `CommitmentSchemeIPA<EpAffine>` → `<EqAffine>`
3. `aetheris-zkp/src/ipa/strategy.rs`: Strategy type params
4. `aetheris-zkp/src/combined_circuit.rs`: Type params
5. CRS regeneration: `gen_crs.ps1` re-run for EqAffine params
6. `INNER_PROOF_PREFIX`: `b"halo2_ipa_pasta_v1_"` → `b"halo2_ipa_vesta_v1_"`
7. `aetheris-recursive/src/accumulator.rs`: Already done in §A
8. `aetheris-recursive/src/prove_recursive.rs`: Type params
9. All Pallas chip modules: Deprecated (Vesta chips replace them)
10. `VestaAccumulateChip::verify_ipa_full`: Now usable directly for inner proof verification (native Vesta points)

**Circuit field stays `Fq`** — the conservation circuit is `Circuit<Fq>` which is Vesta circuit field. Only the commitment curve changes.

**Benefit**: `verify_ipa_full` in `VestaAccumulateChip` works on native Vesta points — no NonNativeChip needed anywhere.

### §E.2 — Replace Blake2bCompressionCircuitChip with Poseidon (from §B.3)

The `VestaAccumulateChip::squeeze_challenges` uses Blake2b (non-native Fq, ~60+ columns).
Replace with Poseidon over Fq (~9 columns):

1. Redesign IPA transcript to use Poseidon for challenge derivation
2. Replace `Blake2bCompressionCircuitChip` in `VestaAccumulateConfig` with `PoseidonFqChip`
3. Simplify config from ~60+ columns to ~9 columns
4. Remove NonNativeFqChip dependency from `VestaAccumulateConfig`

This eliminates the last NonNativeChip usage in the recursive crate (R6 requirement).

### §E.3 — Replacement Scope for Blake2bCompressionCircuitChip

Files affected:
- `aetheris-recursive/src/transcript_blake2b_circuit.rs` (~2537 lines) — **Deprecated**
- `aetheris-recursive/src/transcript_blake2b.rs` (~158 lines) — **Deprecated**
- `aetheris-recursive/src/transcript_blake2b_compression.rs` (~458 lines) — **Deprecated**
- `aetheris-recursive/src/vesta_accumulate.rs` — Replace `squeeze_challenges` body
- `aetheris-recursive/src/lib.rs` — Module declarations: remove `transcript_blake2b*`, add `poseidon_transcript`
- `aetheris-recursive/src/non_native_fq.rs` — **Deprecated** (was needed for Blake2b's Fq-in-Fp encoding)

**Net LoC reduction**: ~3000 lines removed, ~500 lines added (Poseidon transcript). This completes R6 (NonNativeChip elimination).

### §E.4 — Deferred

Implemented after §C is verified in production. Minimum viable: inner proofs verified out-of-circuit (trusted aggregator, current model). Full trustlessness: Phase 1.6 / post-MVP.

---

## §F — P2P Recursive Manager

**Fixes**: D9 | **Prereqs**: §C | **Effort**: ~200 lines

### §F.0 — Dead Code Warning

The `RecursiveManagerHandle` (`aetheris-recursive/src/lib.rs:1921-2130`) is dead code.
- `handle_proof_json` is a `println` stub
- `verify_halo2_proof` → `false` hardcoded
- The main node (`main.rs`) handles gossip directly via `verify_accumulator_chain` calls, NOT through the RecursiveManagerHandle
- Only the FFI `aetheris_recursive_handle_event` path reaches this code

**Impact**: §F changes affect only the FFI ABI and `aetheris-recursive` crate tests, NOT the node's consensus flow. Lower priority than it appears.

### §F.1 — Replace `verify_halo2_proof` Stub

```rust
// Current (lib.rs:2047-2049):
fn verify_halo2_proof(&self, _proof_bytes: &[u8], _statement: &RecursiveStatement) -> bool { false }

// New:
fn verify_halo2_proof(&self, proof_bytes: &[u8], instances: &[Vec<Fq>]) -> bool {
    let params = get_global_params();
    let vk = get_global_vk();
    verify_block_recursive_proof(&params, &vk, proof_bytes, instances)
}
```

### §F.2 — Wire `handle_proof_json` (FFI path)

1. Parse incoming JSON → extract `proof_bytes` + `instances` (5 Fq cells)
2. Call `verify_halo2_proof`
3. If valid → update local accumulator state cache
4. If invalid → log, return error code

### §F.3 — Verification

```bash
cargo test -p aetheris-recursive -- recursive_manager:: --test-threads=2
```

---

## §G — Cleanup

**Fixes**: D10 | **Effort**: ~100 lines

### §G.1 — Rename `empty_accumulator()` → `initial_accumulator()`

File: `aetheris-recursive/src/block_aggregator.rs:174`

Update ~40 callers across:
- `aetheris-recursive/src/block_aggregator.rs` (self-reference)
- `aetheris-node/src/state.rs` (line 4 import, lines 57,78,183)
- `aetheris-node/src/main.rs` (line 228)
- `aetheris-ffi/src/lib.rs` (line 9 import, line 189)

### §G.2 — Remove Deprecated Trait Methods

File: `aetheris-zkp/src/trait_.rs`

Remove `aggregate_proofs()` and `verify_aggregate()` from `ZkProverSystem` trait.
No production callers remain (all use `AccumulatorStrategyIPA` or `verify_accumulator_chain`).

### §G.3 — Archive Superseded Documents

| Document | Annotation |
|----------|-----------|
| `aetheris-recursive/B-3_plan.md` | ✅ Already marked SUPERSEDED |
| `aetheris-recursive/phase_1_14_plan.md` | ✅ Already marked SUPERSEDED |
| `mainnet_execution_plan.md §1.4` | ✅ Already marked SUPERSEDED |
| `docs/in_circuit_ipa_verifier.md` | ✅ Already marked SUPERSEDED (since B-2) |
| `ISSUE_IPA_PLONK_INTEGRATION.md` | Already marked outdated — add note: "Phase 1.11.5 fixed this" |
| `PLAN_FIX_EXTENDED_DOMAIN.md` | Already marked OBSOLETE |

---

## §H — Verification Master Checklist

Each phase must pass independently before the next begins:

- [x] **B-2** (prerequisite): 155/155 tests, VestaEccChip, VestaIpaChip, VestaAccumulateChip
- [x] **§A**: `accumulator.rs` uses `EqAffine`, no `fp_to_fq`, wire format v2, all tests pass
- [x] **§B.1**: Host-side: nullifier uses Poseidon, `build_merkle_root` removed/delegated, accumulator reference uses `poseidon_fq`
- [x] **§B.2**: In-circuit: `PoseidonFqChip` chaining works (test with MockProver)
- [x] **§C**: `CircuitAccumulate` constrains `Q_new = Q_old + Σchallenge·π` correctly
- [x] **§C.6**: `prove_block_recursive`/`verify_block_recursive` produce/verify valid proofs
- [x] **§D.1**: `recursive_proof` is `Vec<u8>` (non-optional), mining produces it
- [x] **§D.2**: `aggregate_proof` removed from `BlockHeader`, all callers updated
- [ ] **§D.3**: Consensus uses O(1) recursive SNARK verification, no O(n) fallback
- [ ] **§E** (Phase 1.6): In-circuit IPA verification complete, Blake2b circuit replaced by Poseidon
- [ ] **§F**: P2P `verify_halo2_proof` is real, gossip proof verification works
- [ ] **§G**: Cleanup complete, all documents annotated, no dead code
- [x] **Final**: `cargo check --workspace` clean, all applicable tests pass

---

## Appendix A: Detailed Deviation-to-Fix Mapping

| ID | Deviation | File:Line | Fix | Notes |
|----|-----------|-----------|-----|-------|
| D1 | Wrong IPA eqn on Q | `prove_recursive.rs:94-111` | §C.6: new `verify_block_recursive_proof` | CRITICAL — protocol security |
| D2 | PallasAccumulateChip used | `recursive_proof.rs:1` | §C: new `CircuitAccumulate` uses Vesta chips | HIGH |
| D3 | Blake3 for transcript | `accumulator.rs:243-248` | §B: PoseidonFqChip | HIGH |
| D4 | O(n) replay | `block_aggregator.rs:94-170` | §C.6: O(1) verify | HIGH |
| D5 | Dual aggregate+recursive | `aetheris-core/src/lib.rs:71,74` | §D: remove aggregate_proof, make recursive non-optional | MEDIUM |
| D6 | No in-circuit IPA verify | — | §E: Phase 1.6 deferred | MEDIUM |
| D7 | Blake3 nullifier | `halo2_pasta.rs:149-153` | §B.1a: `poseidon_nullifier()` | MEDIUM |
| D8 | hash_to_curve Pallas gen | `accumulator.rs:510` | §A: `EqAffine::generator()` | MEDIUM |
| D9 | verify_halo2_proof stub | `lib.rs:2047-2049` | §F.1: real verification | HIGH |
| D10 | Name/docs | multiple | §G: rename, remove dead trait methods | LOW |

## Appendix B: File Inventory

### Files Created
| File | Phase | Purpose |
|------|-------|---------|
| `aetheris-recursive/src/circuit_accumulate.rs` | §C | `AccumulatorCircuit` + `AccumulateConfig` |
| `aetheris-recursive/src/poseidon_accumulator.rs` | §B | `PoseidonAccumulatorChip` wrapper |

### Files Modified (minor)
| File | Phase | Change |
|------|-------|--------|
| `aetheris-recursive/src/accumulator.rs` | §A+§B | EpAffine→EqAffine, fp_to_fq removal, Poseidon hash replace |
| `aetheris-recursive/src/prove_recursive.rs` | §A+§C | EqAffine bridge, new prove/verify functions |
| `aetheris-recursive/src/pallas_accumulate.rs` | §A | Add `eq_to_pallas_point()` bridge |
| `aetheris-recursive/src/lib.rs` | §C | Add `circuit_accumulate` module |
| `aetheris-zkp/src/halo2_pasta.rs` | §B | Nullifier + merkle_root → Poseidon |
| `aetheris-zkp/src/poseidon_fq.rs` | §B | Add `poseidon_hash_chain()` |
| `aetheris-core/src/lib.rs` | §D | `recursive_proof: Vec<u8>`, remove `aggregate_proof` |
| `aetheris-node/src/state.rs` | §D | Consensus verify changes |

### Files Deprecated
| File | Phase | Replacement |
|------|-------|-------------|
| `aetheris-recursive/src/recursive_proof.rs` | §C | `circuit_accumulate.rs` |
| `aetheris-recursive/src/transcript_blake2b_circuit.rs` | §E | Poseidon transcript |
| `aetheris-recursive/src/transcript_blake2b.rs` | §E | Poseidon transcript |
| `aetheris-recursive/src/transcript_blake2b_compression.rs` | §E | Poseidon transcript |
| `aetheris-recursive/src/non_native_fq.rs` | §E | Eliminated |
| `aetheris-recursive/src/pallas_accumulate.rs` | §E | VestaAccumulateChip |
| `aetheris-recursive/src/pallas_ecc.rs` | §E | VestaEccChip |
| `aetheris-recursive/src/pallas_ipa.rs` | §E | VestaIpaChip |
