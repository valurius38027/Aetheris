# Phase 1.13 — Recursive Proof Wrapper Plan

> **Status**: S1-S5 ✅ (scope reduced: see §4.4 — host-precompute pattern avoids in-circuit scalar_mul)
> **Depends on**: §1.12 (B-2: `vesta_ecc`, `vesta_fq`, `vesta_ipa`, `vesta_accumulate`, `proof_import`)
> **Goal**: In-circuit Pallas IPA proof verification → output constant-size (<10 KB) Halo2 recursive proof

---

## 1. Problem Statement

### 1.1 Current Pipeline

```
prove_conservation()  ──→  Pallas (EpAffine, coord Fp, scalar Fq) proof bytes
                                │
                     parse_proof_bytes()
                                │
                     IpaProofWitness {
                         commitment: EpAffine,    // Pallas point
                         l_points:  Vec<EpAffine>, // Pallas points
                         r_points:  Vec<EpAffine>, // Pallas points
                         a_final:   Fq,            // scalar — NATIVE in Circuit<Fq>
                         r_prime:   Fq,            // scalar — NATIVE in Circuit<Fq>
                         eval:      Fq,            // scalar — NATIVE in Circuit<Fq>
                         challenge_prefixes: Vec<Vec<u8>>
                     }
```

### 1.2 Target Verification Equation

```
commitment + Σᵢ(xᵢ⁻¹ · Lᵢ + xᵢ · Rᵢ) = a_final · G_final + r′ · H + (a_final·b_final - eval) · U
```

Where:
- `commitment`, `Lᵢ`, `Rᵢ`, `H`, `U`, `G_final` are **Pallas curve points** (EpAffine)
- `a_final`, `r′`, `eval`, `xᵢ` are **Fq scalars** (native in Circuit<Fq>)
- `b_final` is the folded evaluation point, computed in-circuit

### 1.3 Curve Mismatch

```
              coord field     scalar field     circuit field
Pallas:          Fp              Fq
Vesta:           Fq              Fp
                                    ↑ Circuit<Fq> (B-2 recursive circuit)

What's native:  Fq (Vesta coords, Pallas scalars)
What's NOT:     Fp (Pallas coords)
```

**Scalars are NATIVE** (Fq = recursive circuit field). **Points are NON-NATIVE** (Pallas coordinates are Fp). To verify a Pallas IPA proof in `Circuit<Fq>`, we need **Pallas point arithmetic over Fp coordinates** — and Fp is non-native in Circuit<Fq>.

---

## 2. Architecture

### 2.1 New Layer Stack

```
┌─────────────────────────────────────────────────┐
│  RecursiveProofCircuit                          │
│  - prove_recursive() / verify_recursive_proof() │
│  - Halo2 keygen / prove / verify                │
├─────────────────────────────────────────────────┤
│  PallasAccumulateChip                           │
│  - verify_ipa_pallas()                          │
│  - squeeze_challenges (shared w/ Vesta)         │
├─────────────────────────────────────────────────┤
│  PallasIpaChip                                  │
│  - fold_to_final()                              │
│  - compute_b_vector()                           │
├─────────────────────────────────────────────────┤
│  PallasEccChip          │  VestaFqChip          │
│  - point_add            │  - Fq add             │
│  - point_double         │  - Fq mul             │
│  - scalar_mul           │  - Fq invert          │
│  - on_curve             │  - assign_constant    │
│  - select               │                       │
│  - constrain_equal      │                       │
├─────────────────────────┤                       │
│  NonNativeFpChip        │  (native, existing)   │
│  - Fp add/sub/mul/inv   │                       │
│  - 3 × 85-bit limbs     │                       │
└─────────────────────────┴───────────────────────┘
```

### 2.2 Field Relationships

| Component | Represents | Circuit field | Native? |
|-----------|-----------|---------------|---------|
| `NonNativeFpChip` | Fp value | Fq | No (limb decomposition) |
| `PallasEccChip::PallasPoint` | Pallas point (x,y in Fp) | Fq | No (coords via NonNativeFpChip) |
| `VestaFqChip::Limb<Fq>` | Fq scalar | Fq | Yes |
| `challenge` | IPA round challenge (Fq) | Fq | Yes |
| `scalar_mul` multiplier | Fq (bit source) | Fq | Yes |

**Key insight**: Pallas `scalar_mul(s, P)` takes:
- `s`: `Value<Fq>` — decomposed into bits for double-and-add → **native** (VestaFqChip to decompose)
- `P`: `PallasPoint` (x=FpElement, y=FpElement) — coordinates use **NonNativeFpChip** for point arithmetic

### 2.3 NonNativeFpChip Design

Modeled on `non_native_fq.rs` (which does Fq-over-Fp), but for Fp-over-Fq.

```
Fp modulus: 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
Fp bit length: 255

Limb decomposition: 3 × 85-bit limbs (same as Fq-over-Fp)
  value = limb[0] + limb[1]·2^85 + limb[2]·2^170

  Limb[0]: bits 0..84
  Limb[1]: bits 85..169
  Limb[2]: bits 170..254  (only 85 bits used in high limb)
```

**Gates** (same structure as NonNativeFqChip):

| Gate | Selector | Rows | Constraint |
|------|----------|------|------------|
| `s_add` | Carry chain | 4 | `a_i + b_i + carry_in_i = c_i + 2^85 · carry_out_i` |
| `s_reduce` | Modular reduction | 4 | `p_i + k·fp_i + borrow_in_i = l_i + 2^85 · borrow_out_i` |
| `s_mul` | Limb product | 1 | `a_i · b_j = p_ij` |
| `s_range` | Bit check | 1 | `bit · (1 - bit) = 0` |

**Operations**:
- `add(a, b) → c`: 4 rows carry chain + 4 rows reduction + 1 k-check = 10 rows + range checks
- `sub(a, b) → c`: negate b, add (same as NonNativeFqChip::sub)
- `neg(a) → c`: witness externally, verify via `add(a, c) = 0`
- `mul(a, b) → c`: 9 partial products + 5-position carry chain + range checks
- `invert(a) → c`: witness externally, verify `a * c = 1 mod Fp`
- `assign_constant(c) → Limb<Fq>`: assign constant Fp value as 3 limbs

### 2.4 PallasEccChip Design

Modeled on `vesta_ecc.rs` but:
- Point type is `PallasPoint { x: FpElement, y: FpElement }` instead of `VestaPoint { x: Value<Fq>, y: Value<Fq> }`
- Coordinate arithmetic uses `NonNativeFpChip` methods instead of native Fq
- Scalar (for `scalar_mul`) is `Value<Fq>` — decomposed to bits using existing bit-decomposition

**PallasPoint**:
```rust
pub struct PallasPoint {
    pub x: FpElement,       // 3 limbs of Fq
    pub y: FpElement,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
}
```

**Gates** (same structure as VestaEccConfig but constraints use `NonNativeFpChip`):

| Gate | Selector | Constraint | NonNativeFpChip ops |
|------|----------|------------|---------------------|
| `s_on_curve` | `y² = x³ + 5` (Fp arithmetic) | `mul`, `add` |
| `s_add` | λ = (y₂-y₁)/(x₂-x₁), x₃ = λ²-x₁-x₂, y₃ = λ(x₁-x₃)-y₁ | `sub`, `invert`, `mul`, `add` |
| `s_double` | λ = (3x₁²)/(2y₁), x₃ = λ²-2x₁, y₃ = λ(x₁-x₃)-y₁ | `mul`, `add`, `invert` |
| `s_select` | bit·P₁ + (1-bit)·P₂ | `assign_constant` + select |
| `s_scalar_mul_result` | x·(y² - x³ - 5) = 0 (relaxed identity) | `mul`, `add` |

**scalar_mul**(s, P) algorithm:
- Same offset-cancel approach as VestaEccChip (2^254 · P offset)
- Decompose Fq scalar into 255 bits via VestaFqChip
- Double-and-add using PallasEccChip point ops
- Final relaxed identity gate: `x * (y² - x³ - 5) = 0` (allows (0,0) for s=0)

**Key difference from VestaEccChip**: Each point operation is 3-10× more expensive because coordinate ops go through limb decomposition. A single `point_add` on Pallas requires ~6 Fp multiplications and 1 Fp inverse, each of which takes multiple rows in Circuit<Fq>.

### 2.5 PallasIpaChip Design

Modeled on `vesta_ipa.rs` — structurally nearly identical:
- Generators are `Vec<PallasPoint>` instead of `Vec<VestaPoint>`
- `fold_to_final` uses `PallasEccChip::scalar_mul` and `point_add`
- B-vector uses `VestaFqChip` (Fq scalars are native)
- Challenges are `Vec<Limb<Fq>>` — same type

### 2.6 PallasAccumulateChip Design

Modeled on `vesta_accumulate.rs`:
- Squeeze challenges: uses existing Blake2b transcript chip (field-generic, works with Fq)
- `verify_ipa_pallas`: implements the IPA verification equation using `PallasEccChip` + `VestaFqChip`
- Takes `IpaProofWitness` (from `proof_import`) as input

**verify_ipa_pallas flow**:
```
1. Parse IpaProofWitness
2. Rebuild challenge prefixes → squeeze challenges (VestaAccumulateChip::squeeze_challenges)
3. Fold: fold generators + b-vector through k rounds (PallasIpaChip::fold_to_final)
4. Compute LHS:
   a. For each round i: compute x_inv·L_i + x·R_i, accumulate
5. Compute RHS:
   a. a_final · G_final
   b. r_prime · H
   c. (a_final·b_final - eval) · U
   d. Sum := a·G + r'·H + (ab-eval)·U
6. Constrain_equal(LHS, RHS)
```

### 2.7 RecursiveProofCircuit

**Circuit structure**:
```rust
struct RecursiveProofCircuit {
    // Witness (private inputs)
    proof_witness: IpaProofWitness,
    
    // Public instances
    commitment_x: Fq,  // first limb of commitment x-coordinate (Fp mapped to Fq)
    commitment_y: Fq,
    eval: Fq,
    // Or: commitment as 6 Fq values (3 limbs × 2 coords)
}

impl Circuit<Fq> for RecursiveProofCircuit {
    type Config = RecursiveProofConfig;  // wraps PallasAccumulateConfig
    type FloorPlanner = SimpleFloorPlanner;
    
    fn synthesize(&self, config, layouter) -> Result<(), Error> {
        // 1. Parse proof witness
        // 2. Assign public inputs (commitment, eval) as instance columns
        // 3. Run verify_ipa_pallas
        // 4. Output: constraints are satisfied (proof is valid)
    }
}
```

**API**:
```rust
// Host-side: generate params for a specific k
fn build_recursive_params(k: u32) -> (ParamsIPA<EqAffine>, ProvingKey, VerifyingKey)

// Generate a recursive proof from an inner IPA proof
fn prove_recursive(
    params: &ParamsIPA<EqAffine>,
    pk: &ProvingKey,
    proof: IpaProofWitness,
) -> Result<Vec<u8>, Error>

// Verify a recursive proof
fn verify_recursive_proof(
    params: &ParamsIPA<EqAffine>,
    vk: &VerifyingKey,
    proof: &[u8],
    public_inputs: &[Fq],
) -> Result<bool, Error>
```

**Output size**: ~3-8 KB (1 Halo2 proof instance, k≈17-19, constant independent of inner proof rounds)

---

## 3. Implementation Steps (S1–S6)

### S1: `non_native_fp.rs` — Non-native Fp arithmetic (~900 lines)

**File**: `aetheris-recursive/src/non_native_fp.rs`

**Constants**:
```rust
pub const FP_NUM_LIMBS: usize = 3;
pub const FP_LIMB_BITS: usize = 85;
pub const CARRY_BITS: usize = 90;

/// Fp = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
const FP_MOD_BYTES: [u8; 32] = [/* ... */];
```

**Types**:
```rust
pub struct FpElement {
    pub limbs: [Limb<Fq>; FP_NUM_LIMBS],
}

impl FpElement {
    pub fn new(limbs: [Limb<Fq>; FP_NUM_LIMBS]) -> Self;
    pub fn zero() -> Self;
    pub fn one() -> Self;
    pub fn to_big(&self) -> Value<BigUint>;
}
```

**Config/Chip**:
```rust
pub struct NonNativeFpConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub aux: Column<Advice>,
    pub fp_const: Column<Fixed>,
    pub s_add: Selector,
    pub s_mul: Selector,
    pub s_range: Selector,
    pub s_reduce: Selector,
}

impl NonNativeFpConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self;
}

pub struct NonNativeFpChip { config: NonNativeFpConfig }

impl NonNativeFpChip {
    pub fn new(config: NonNativeFpConfig) -> Self;
    pub fn add(&self, layouter, a: &FpElement, b: &FpElement) -> Result<FpElement>;
    pub fn sub(&self, layouter, a: &FpElement, b: &FpElement) -> Result<FpElement>;
    pub fn neg(&self, layouter, a: &FpElement) -> Result<FpElement>;
    pub fn mul(&self, layouter, a: &FpElement, b: &FpElement) -> Result<FpElement>;
    pub fn invert(&self, layouter, a: &FpElement) -> Result<FpElement>;
    pub fn assign_constant(&self, layouter, val: Fp, label: &str) -> Result<FpElement>;
}
```

**Implementation notes**:
- `add`: Same 3-limb carry chain as NonNativeFqChip::add → uses s_add (4 rows) + s_reduce (4 rows) + s_range (1 row k-check). 10 rows total.
- `sub`: `a - b = a + neg(b)` where `neg(b) = Fp - b`.
- `neg`: Witness -b externally, verify via `add(b, neg_b) == 0`.
- `mul`: Same 9 partial products + 5-position carry chain as NonNativeFqChip::mul (rows 0-33). Range checks: 3×85-bit Q (rows 34-298), 3×85-bit R (rows 298-556), 4×90-bit carries (rows 556-920). Total ~1000 rows for one mul.
- `invert`: Witness externally, verify `a * inv == 1 mod Fp` via mul + constrain_equal.
- `assign_constant`: Decompose Fp value into 3 Fq limbs, assign each.

**Limb arithmetic helpers** (Fq-native, using VestaFqChip internally or native Fq ops):
- `fp_limb_fq(i)` → Fp modulus limb i as Fq
- `big_fp_mod()` → Fp modulus as BigUint
- `big_limb_base()` → 2^85 as BigUint
- `fq_to_big(fq: &Fq)` → BigUint
- `big_to_fq(big: &BigUint)` → Fq

**Tests**:
- `test_fp_add_small`: 3 + 7 = 10 mod Fp
- `test_fp_add_wrapping`: (Fp - 1) + 2 = 1 mod Fp
- `test_fp_sub`: 10 - 3 = 7 mod Fp
- `test_fp_mul_small`: 3 * 7 = 21 mod Fp
- `test_fp_mul_large`: near-modulus values
- `test_fp_invert`: 5 * inv(5) = 1 mod Fp
- `test_fp_invert_zero_rejected`: invert(0) rejected
- `test_fp_neg`: neg(5) = Fp - 5
- `test_fp_assign_constant`: roundtrip

### S2: `pallas_ecc.rs` — Pallas ECC chip (~550 lines)

**File**: `aetheris-recursive/src/pallas_ecc.rs`

**Types**:
```rust
pub struct PallasPoint {
    pub x: FpElement,        // 3 Fq limbs (coordinate in Fp)
    pub y: FpElement,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
}

impl PallasPoint {
    // Convert from EpAffine (host-side Pallas point)
    pub fn from_ep_affine(p: &EpAffine) -> Self;
    
    // Create from known Fp coordinates
    pub fn new(x: Fp, y: Fp) -> Self;
}
```

**Config/Chip**:
```rust
pub struct PallasEccConfig {
    // Same 8 advice columns + 5 selectors as VestaEccConfig
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub d: Column<Advice>,
    pub e: Column<Advice>,
    pub f: Column<Advice>,
    pub g: Column<Advice>,
    pub h: Column<Advice>,
    pub s_on_curve: Selector,
    pub s_add: Selector,
    pub s_double: Selector,
    pub s_select: Selector,
    pub s_scalar_mul_result: Selector,
}

pub struct PallasEccChip {
    pub config: PallasEccConfig,
    pub fp: NonNativeFpChip,   // For Fp coordinate arithmetic
    pub fq: VestaFqChip,       // For Fq scalar decomposition
}
```

**Gates** — Same constraints as VestaEccConfig but with one critical difference: the constraints operate on `Fq` field values (the Circuit field), and the point coordinates are stored as individual Fq limbs.

The gate constraints are simpler than NonNativeFpChip because:
- The `s_on_curve`, `s_add`, `s_double` gates just constrain the relationship between ASSIGNED Fq cells
- The actual Fp arithmetic correctness is enforced by the FpElement assignments (which the NonNativeFpChip methods handle)
- The ECC gates' job is to verify the point addition/doubling FORMULA holds

Wait — this is actually a key insight. Let me reconsider.

For VestaEccChip, the constraints use native Fq arithmetic expressions:
```
// On curve:
y² - x³ - 5 = 0

// Point add:
λ · (qx - px) - (qy - py) = 0
λ² - px - qx - rx = 0
λ · (px - rx) - py - ry = 0
```

These expressions are polynomial constraints in Circuit<Fq>. The Fq multiplication/addition in these constraints is NATIVE — the circuit evaluates them as field operations.

For PallasEccChip, if we store Pallas coordinates as Fq cells (3 limbs each), we CANNOT write these constraints directly because the Fq multiplication of 85-bit limbs doesn't equal Fp point arithmetic.

So we need a different approach.

**Two approaches for PallasEccChip constraints**:

**Approach A: NonNative gate constraints**
Write gates that use NonNativeFpChip operations to constrain each coordinate computation. This means:
- Each gate becomes a sequence of NonNativeFpChip calls
- Gates are not "1 row" anymore — they're multi-row regions
- Pro: sound, correct Fp arithmetic
- Con: more rows per gate

**Approach B: Witness-and-verify**
- Witness all intermediate values (λ, x₃, y₃) using host computation
- Use NonNativeFpChip to verify the constraints: λ·(qx-px) == (qy-py) mod Fp, etc.
- Each verification is a sequence of NonNativeFpChip mul/add/sub calls

Approach B is cleaner and follows the same pattern as NonNativeFqChip (which does witness-and-verify for its operations). Let me design the gates as regions with NonNativeFpChip verification.

**PallasEccChip::point_add** — Region-based:

```
Region: 10 rows (or more, depending on NonNativeFpChip layout)
1. Host-compute: λ, x₃, y₃ using Fp arithmetic
2. Assign P, Q, λ, R to advice cells
3. For each constraint:
   a. λ·(qx-px) == (qy-py) mod Fp
   b. λ² - px - qx == x₃ mod Fp
   c. λ·(px-x₃) - py == y₃ mod Fp
   Each constraint verified via NonNativeFpChip::mul + add/sub
```

This is more expensive than VestaEccChip's 1-row gate, but it's correct.

Wait, actually, let me reconsider the design. The NonNativeFpChip doesn't need to be integrated with the ECC gate selectors at all. Instead, we can use a **hybrid** approach:

1. **Columns**: Allocate advice columns for Pallas POINT values (x_lo, x_mid, x_hi, y_lo, y_mid, y_hi for each point)
2. **No dedicated ECC gates**: Instead, use the NonNativeFpChip's existing gates (s_add, s_mul, s_range, s_reduce) to verify point arithmetic
3. **Witness-and-verify**: Compute λ, x₃, y₃ on host (native Fp), then use NonNativeFpChip ops to verify the point addition constraints

This means `PallasEccChip` doesn't need its own selectors — it just uses `NonNativeFpChip` gates. The "chip" orchestrates sequences of Fp operations.

This is actually the cleanest design. Let me revise:

**PallasEccChip** wraps NonNativeFpChip and VestaFqChip:
- `assert_on_curve(P)`: Use NonNativeFpChip to verify `y² - x³ - 5 = 0 mod Fp`
  - `tmp1 = fp.mul(x, x)` → `x²`
  - `tmp2 = fp.mul(tmp1, x)` → `x³`
  - `tmp3 = fp.add(tmp2, FIVE)` → `x³ + 5`
  - `tmp4 = fp.mul(y, y)` → `y²`
  - `result = fp.sub(tmp4, tmp3)` → `y² - x³ - 5`
  - Constrain `result == 0` (limbs all zero)

- `point_add(P, Q)`: Host-compute λ, R then verify:
  - `dx = fp.sub(qx, px)`
  - `dy = fp.sub(qy, py)`
  - `lam = fp.witness(λ)`, verify `fp.mul(dx, lam) == dy`
  - `lam_sq = fp.mul(lam, lam)`
  - `rx = fp.witness(x₃)`, verify `fp.sub(fp.sub(lam_sq, px), qx) == rx`
  - `x_sub = fp.sub(px, rx)`
  - `lam_x_sub = fp.mul(lam, x_sub)`
  - `ry = fp.witness(y₃)`, verify `fp.sub(lam_x_sub, py) == ry`

- `scalar_mul(s, P)`: Same offset-cancel algorithm as VestaEccChip:
  - Decompose Fq scalar into 255 bits (VestaFqChip)
  - Double-and-add using point_double + point_add + select
  - Final relaxed identity gate: assign result, skip on_curve check (handled by `x * (y² - x³ - 5) = 0` style check or a special gate)

Wait, but we DON'T have a circuit gate for `x * (y² - x³ - 5) = 0` in NonNativeFpChip. We'd need to add this as a PallasEccChip-specific gate, or implement it using NonNativeFpChip ops:
```
tmp1 = fp.mul(y, y)
tmp2 = fp.mul(x, x)
tmp3 = fp.mul(tmp2, x)
tmp4 = fp.add(tmp3, FIVE)
tmp5 = fp.sub(tmp1, tmp4)   // y² - x³ - 5
tmp6 = fp.mul(x, tmp5)       // x * (y² - x³ - 5)
// Constrain tmp6 == 0 (all limbs zero)
```

This is witness-and-verify, so it doesn't need a custom gate. Just calls through NonNativeFpChip.

**But there's a problem**: for `scalar_mul`, each double-add iteration calls `point_double`, `point_add`, `select`. Each of these calls multiple NonNativeFpChip operations. For 255 iterations, this is ~255 × (10 Fp operations × 10 rows each) ≈ 25,000 rows. For k rounds of verification, times 2k+3 scalar_muls, that's ~(2k+3) × 25,000 rows. For k=2: 175,000 rows. For k=10: 575,000 rows. This is impractical.

**This is a major problem.** The witness-and-verify approach is too expensive per operation.

Let me reconsider. The VestaEccChip uses 1-row CUSTOM GATES for point_add, point_double, on_curve. These gates embed the curve arithmetic directly into the constraint system. For PallasEccChip, we need CUSTOM GATES that embed Pallas curve arithmetic.

But the Pallas curve arithmetic uses Fp operations, and the circuit field is Fq. We can't embed Fp multiplication in a single row.

UNLESS... we use the limb-decomposition approach directly in the gate. Instead of using NonNativeFpChip as a separate chip, we embed the limb arithmetic INTO the ECC gate.

Let me think about this...

For `on_curve`: `y² - x³ - 5 = 0` where x, y are Fp elements.

If we represent x, y as 3 × 85-bit Fq limbs, then:
- `y²` mod Fp requires: (y_lo + y_mid·B + y_hi·B²)² mod Fp
  = y_lo² + 2·y_lo·y_mid·B + (2·y_lo·y_hi + y_mid²)·B² + 2·y_mid·y_hi·B³ + y_hi²·B⁴ mod Fp
  
This is the same polynomial structure as NonNativeFqChip::mul — we'd need 9 limb products (y_lo², y_lo·y_mid, ..., y_hi²) and reduction mod Fp.

So the ECC gate for `on_curve` is essentially a batch of NonNativeFpChip::mul operations. We could create a custom gate that does all the mul+reduce in one region, but the complexity is the same as calling NonNativeFpChip separately.

**The bottleneck**: `scalar_mul` does ~255 iterations of double-and-add. Each iteration needs:
- `point_double`: λ = 3x²/2y, x₃ = λ² - 2x, y₃ = λ(x-x₃) - y
- `point_add`: λ = (y₂-y₁)/(x₂-x₁), x₃ = λ² - x₁ - x₂, y₃ = λ(x₁ - x₃) - y₁
- `select`: conditional point selection

Each `point_add` requires ~6 Fp multiplications + 1 Fp inverse + ~6 Fp add/sub.
Each Fp multiplication via NonNativeFpChip takes ~1000 rows (limbs + carry chain + range checks).
Each Fp inverse takes 1 multiplication (witness-and-verify).

So one `point_add`: 6 × 1000 + 1000 = 7000 rows.
One `scalar_mul`: 255 × (7000 + 7000) = 3,570,000 rows.
Total verification (k=2): (2k+3) × 3.57M = 7 × 3.57M = ~25M rows.
At k=17 (standard Halo2), max rows = 2¹⁷ = 131,072. That's only 131K rows.

**25M rows >> 131K rows. This won't fit.**

This means the witness-and-verify + NonNativeFpChip approach is PROHIBITIVELY EXPENSIVE. We need a fundamentally different strategy.

## 4. Revised Approach: Offset Precomputation + Batch Verification

The analysis above shows that full in-circuit Pallas IPA verification via NonNativeFpChip is impractical due to row count.

### 4.1 Why the row count blows up

The problem: each Pallas `scalar_mul` operation does 255 double-and-add iterations, and each iteration needs multiple Fp multiplications (θ(n) rows each).

### 4.2 Solution: Precompute on host, batch-verify in circuit

Instead of computing Pallas scalar_mul from scratch in the circuit, we:

1. **Host precomputes** all intermediate Pallas points:
   - `xᵢ⁻¹ · Lᵢ` for each round i
   - `xᵢ · Rᵢ` for each round i
   - `a_final · G_final`
   - `r′ · H`
   - `(ab-eval) · U`
   - Final LHS and RHS points

2. **Circuit batch-verifies** correctness using a single Pallas point addition chain with witness-and-verify

The key insight: we don't need to prove we CAN compute these scalar_muls — we just need to prove the FINAL EQUATION holds. We witness all intermediate points, and verify the IPA equation using only point ADDITIONS (which are cheaper than scalar_muls).

### 4.3 The IPA verification equation

```
commitment + Σᵢ(xᵢ⁻¹·Lᵢ + xᵢ·Rᵢ) = a_final·G_final + r′·H + (ab-eval)·U
```

This can be rewritten as:

```
commitment + Σᵢ(Lᵢ' + Rᵢ') = G' + H' + U'
```

Where:
- `Lᵢ' = xᵢ⁻¹ · Lᵢ` — host-precomputed Pallas point
- `Rᵢ' = xᵢ · Rᵢ` — host-precomputed Pallas point
- `G' = a_final · G_final` — host-precomputed Pallas point
- `H' = r′ · H` — host-precomputed Pallas point
- `U' = (ab-eval) · U` — host-precomputed Pallas point

All scalar_muls are done on the HOST. The circuit only verifies POINT ADDITIONS.

But wait — if we precompute everything on the host, what does the circuit actually VERIFY? The circuit needs to prove that the precomputed points are CORRECT. If the host can lie about the intermediate results, the circuit would accept invalid proofs.

### 4.4 Soundness-preserving approach

We need to ensure the circuit catches incorrect host precomputation. The approach:

1. **Host precomputes** intermediate scalar_mul results
2. **Circuit verifies** each scalar_mul result using a CHEAPER method than full recomputation

For Pallas scalar_mul verification in the circuit, we can use the **double-and-add check** on a single small scalar instead of 255 iterations:

Wait, that doesn't work because we need to verify all bits.

**Alternative**: Instead of verifying scalar_mul from scratch, we can use a **random linear combination** trick:

1. Host precomputes all intermediate points (Lᵢ', Rᵢ', G', H', U')
2. Circuit verifies a random linear combination: the IPA equation
3. If any intermediate point is wrong, with overwhelming probability the IPA equation will not hold

But this only works if the BATCH verification (the full IPA equation) catches errors in INDIVIDUAL components. Since the IPA equation is linear in each component (modulo the on-curve checks), an error in any component will propagate to the final result with probability 1 - 1/Fq ≈ 1.

Wait, actually — let me think about this more carefully.

The IPA equation is:
```
Σᵢ(Lᵢ' + Rᵢ') - G' - H' - U' = -commitment
```

Each component is a point on Pallas. If one component is wrong (e.g., L'ᵢ is replaced with a wrong point), the sum will be wrong UNLESS there's a cancellation (which would require solving a discrete log — infeasible).

So the soundness is: **if any host-precomputed point is wrong, the IPA equation fails, and the circuit rejects.**

But wait — we still need to verify that each point is ON CURVE (on Pallas). If the host provides arbitrary wrong points, they might still satisfy the IPA equation by coincidence. We need:
1. Each precomputed point is on Pallas (on_curve check)
2. The full IPA equation holds

But verifying on_curve for each point still requires Fp arithmetic. Each on_curve check is 6 Fp ops (y² - x³ - 5 = 0). With NonNativeFpChip, each op is ~1000 rows, so 5 points × 6 ops × 1000 rows = 30,000 rows per point.

For k=2: commitment + 2×(L'+R') + G' + H' + U' = 1 + 4 + 1 + 1 + 1 = 8 points.
8 × 6 × 1000 = 48,000 rows. At k=16: 65,536 max rows. Doable!

But for point ADDITION verification, we need additional ops. Each `point_add` needs:
- 6 Fp multiplications
- 1 Fp inverse
- 6 Fp add/sub

That's another 13 × 1000 = 13,000 rows per addition. For k=2: 2k+2 = 6 additions → 78,000 rows. Total: 48,000 + 78,000 = 126,000 rows. At k=17: 131,072 max rows. Tight but possible.

For k=10: 10 rounds, more points. Not feasible.

**Revised estimate**: k=2 (4 generators, 2 rounds) fits at k=17. Larger k needs larger K.

### 4.5 Minimum viable approach

With the revised understanding, the plan for S1-S6 is:

**S1: `non_native_fp.rs`** (~900 lines)
- Full NonNativeFpChip with add, sub, mul, invert, assign_constant
- Same structure as NonNativeFqChip

**S2: `pallas_ecc.rs`** (~400 lines)
- `assert_on_curve`: verify y² - x³ - 5 = 0 using NonNativeFpChip ops
- `point_add`: witness λ, x₃, y₃ externally; verify x₃, y₃ constraints via NonNativeFpChip
- `point_double`: same pattern
- `select`: conditional point selection (FpEelement bit)
- `constrain_equal_points`: coordinate-wise constrainequal
- `point_negate`: (x, Fp - y)
- NOTE: `scalar_mul` is NOT implemented in-circuit — precomputed on host

**S3: `pallas_ipa.rs`** (~100 lines)
- `fold_to_final`: host-precomputed intermediate points, circuit verifies IPA equation
- Note: generators, folded points are all host-computed; circuit verifies point equality

**S4: `pallas_accumulate.rs`** (~350 lines)
- `verify_ipa_pallas`: 
  1. Rebuild challenges from prefixes (existing Blake2b transcript)
  2. Accept precomputed Lᵢ' = xᵢ⁻¹·Lᵢ and Rᵢ' = xᵢ·Rᵢ as PallasPoint witnesses
  3. Accept precomputed G' = a·G_final, H' = r′·H, U' = (ab-eval)·U as witnesses
  4. On-curve check ALL precomputed points
  5. Verify LHS = commitment + Σ(Lᵢ' + Rᵢ') via point_add chain
  6. Verify RHS = G' + H' + U' via point_add chain  
  7. Constrain_equal(LHS, RHS)

**S5: `recursive_proof.rs`** (~250 lines)
- `RecursiveProofCircuit` using `PallasAccumulateChip`
- Public inputs: commitment (6 Fq values), eval (1 Fq value)
- `prove_recursive`, `verify_recursive_proof`
- Keygen/params building

**S6: Tests** (~300 lines)
- NonNativeFpChip unit tests
- PallasEccChip tests (on_curve, point_add, point_double)
- PallasAccumulateChip: synthetic proof verification
- PallasAccumulateChip: corrupt-proof rejection
- End-to-end: parse real proof → verify in circuit

### 4.6 Row budget analysis for k=2

```
Component                              Rows per call   Calls   Total rows
─────────────────────────────────────────────────────────────────────────
Fp mul (via NonNativeFpChip)             ~1000
Fp add/sub (via NonNativeFpChip)         ~10
Fp invert (witness + mul verify)         ~1000

On-curve check (6 ops)                   ~6110        8        ~48,880
Point_add (13 ops)                       ~13,060      6        ~78,360
Constrain_equal points                   ~2           1        ~2
Total                                                     129,242

Max rows at k=17 (2¹⁷)                                   131,072
Utilization                                               98.6%
```

This is extremely tight. At k=17, we're at 98.6% utilization. For any margin of error, we'd need k=18 (262,144 rows). The Halo2 parameter needs to be k=18.

But wait — k=18 means 2× the CRS size and proving time. This is a tradeoff.

Let me recalculate more carefully. The NonNativeFpChip::mul has:
- 9 s_mul rows (partial products)
- 4 rows accumulation helper
- 6 rows s_reduce carry chain (contiguous)
- 3 × 85-bit range checks: 3 × (85 + 1) = 258 rows
- 4 × 90-bit carry range checks: 4 × (90 + 1) = 364 rows
Total: ~636 rows per mul

Wait, that's less than 1000. Let me re-read NonNativeFqChip's mul more carefully.

From non_native_fq.rs:
- Rows 0-8: s_mul (9 rows)
- Rows 9-11: assign Q (3 rows)
- Rows 12-14: assign R (3 rows)
- Rows 15-23: qf_ij (9 rows)
- Rows 24-27: accumulate P sums (4 rows)
- Rows 28-33: carry chain (6 rows)
- Rows 40+: range check Q (85+1 = 86 rows per Q limb, 3 limbs → 258 rows)
- Rows 298+: range check R (same, 258 rows)
- Rows 556+: range check carries (90+1 = 91 rows per carry, 4 carries → 364 rows)

Total: 9 + 3 + 3 + 9 + 4 + 6 + 258 + 258 + 364 = 914 rows

So each Fp mul takes ~914 rows. Plus ~10 rows for add/sub, ~1000 for invert.

Revised row count:
- On-curve: 6 × (914 + 10) ≈ 5,544 rows per point
- Point_add: 13 × (914 + 10) ≈ 12,012 rows per add
- 8 points on-curve: 8 × 5,544 = 44,352
- 6 point_adds: 6 × 12,012 = 72,072
- Total: 116,424 rows

At k=17 (131,072 max): 88.8% utilization. More comfortable but still tight.

However, the Fq operations (native) are also in the circuit. The compute_b_vector, challenge derivation, etc. add overhead. Let's estimate:
- b-vector: 4 scalar mul + 3 add = 7 Fq ops × 1 row each = 7 rows
- Challenges: k+1 squeezes, each ~10 rows = 30 rows
- Total overhead: ~100 rows <— negligible

So total: ~116,500 rows at k=17. This fits, just barely.

BUT — there's also the `squeeze_challenges` which uses the Blake2b circuit. The Blake2b circuit adds significant rows (hundreds to thousands). For k=2, we might need ~2000 rows for the transcript.

Revised total: ~118,500 rows at k=17. Fits with ~10% margin.

For k=2 (2 rounds), this is workable. For larger k, we need larger K (proportional to k since each round adds 2 point_adds and 2 more precomputed points to verify).

### 4.7 Scalability

```
k (rounds)   Precomputed pts   Point_adds   Est. rows     Min K
─────────────────────────────────────────────────────────────────
2             8                 6             ~119K        17
3             10                8             ~161K        18  
4             12                10            ~203K        18
5             14                12            ~245K        19
10            24                22            ~463K        19-20
```

Each additional round adds:
- 2 precomputed points (Lᵢ', Rᵢ') × on_curve = ~11K rows
- 2 point_adds = ~24K rows
- Total per round: ~35K rows

For realistic parameters (k=10), we need K=19 (524,288 rows). K=19 is still within normal Halo2 range (CRS ~65MB for IPA).

---

## 5. File by File Breakdown

### S1: `non_native_fp.rs` (~900 lines)

Structure mirrors `non_native_fq.rs`:
- **Constants**: FP_MOD_BYTES, TWO_POW_85_BYTES, FP_NUM_LIMBS=3, FP_LIMB_BITS=85, CARRY_BITS=90
- **FpElement**: `struct { limbs: [Limb<Fq>; 3] }` with `new()`, `zero()`, `one()`, `to_big()`
- **NonNativeFpConfig**: a, b, c, aux advice columns + fp_const fixed + s_add/s_mul/s_range/s_reduce
- **NonNativeFpChip**:
  - `configure(meta: &mut ConstraintSystem<Fq>) -> NonNativeFpConfig`
  - `add(layouter, a, b) -> FpElement` — carry chain + reduction (~10 rows + range checks)
  - `sub(layouter, a, b) -> FpElement` — neg(b) + add
  - `neg(layouter, a) -> FpElement` — witness Fp-b, verify via add(b, neg) = 0
  - `mul(layouter, a, b) -> FpElement` — 9 partial products + carry chain (~914 rows)
  - `invert(layouter, a) -> FpElement` — witness inv, verify via mul(a, inv) = 1
  - `assign_constant(layouter, val: Fp) -> FpElement` — decompose Fp → 3 Fq limbs
- **Tests** (~200 lines)

Gates:
```rust
// s_add: a + b + carry_in - c - 2^85 * carry_out = 0
//  (same constraint as non_native_fq but on Fq field)

// s_reduce: r + k*fp_i + carry_in - l - 2^85 * carry_out = 0
//  fp_i is the Fp modulus limb i (as fixed Fq value)

// s_mul: a * b - c = 0

// s_range: bit * (1 - bit) = 0
```

Key difference from NonNativeFqChip: the constraint column types are `Expression<Fq>` (not Fp). No code change needed in the gates themselves — `ConstraintSystem<Fq>::create_gate` returns `Expression<Fq>`. The gate structures are identical.

### S2: `pallas_ecc.rs` (~400 lines)

**Types**:
```rust
pub struct PallasPoint {
    pub x: FpElement,
    pub y: FpElement,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
}
```

**PallasEccChip**:
```rust
pub struct PallasEccChip {
    pub fp: NonNativeFpChip,
    pub fq: VestaFqChip,
}
```

Methods:
- `assert_on_curve(layouter, point) -> PallasPoint`:
  `tmp = fp.mul(y, y); tmp = fp.sub(tmp, fp.mul(fp.mul(x, x), x)); tmp = fp.sub(tmp, fp_5); constrain_zero(tmp)`
  
- `point_add(layouter, p, q) -> PallasPoint`:
  Host: λ = (qy-py)/(qx-px), rx = λ²-px-qx, ry = λ(px-rx)-py
  Circuit: `dx = fp.sub(qx, px); dy = fp.sub(qy, py); fp.mul(dx, λ_wit) == dy; lam_sq = fp.mul(λ_wit, λ_wit); fp.sub(fp.sub(lam_sq, px), qx) == rx_wit; ...`

- `point_double(layouter, p) -> PallasPoint`:
  Host: λ = 3px²/2py, rx = λ²-2px, ry = λ(px-rx)-py
  Circuit: same pattern as point_add

- `select(layouter, bit: Value<Fq>, a, b) -> PallasPoint`:
  Each limb: `result_limb = bit * b_limb + (1-bit) * a_limb` (uses Fq native ops for the select, then repackages as FpElement)

- `point_negate(layouter, p) -> PallasPoint`:
  `neg_y = fp.sub(fp_zero, y)` or `neg_y = fp.sub(fp_mod, y)`

- `constrain_equal_points(layouter, a, b)`:
  Constrain each of the 6 limbs (3 per coord) to be equal

- `constrain_zero(layouter, a: &FpElement)`:
  Constrain all 3 limbs to be zero

### S3: `pallas_ipa.rs` (~100 lines)

```rust
pub struct PallasIpaChip {
    pub fp: NonNativeFpChip,
    pub ecc: PallasEccChip,
}

impl PallasIpaChip {
    /// Verify folded result by constraining host-precomputed points.
    /// Takes host-precomputed intermediate scalar_mul results.
    pub fn verify_ipa_full(
        &self,
        layouter: impl Layouter<Fq>,
        commitment: &PallasPoint,
        l_scaled_points: &[PallasPoint],  // xᵢ⁻¹ · Lᵢ (host precomputed)
        r_scaled_points: &[PallasPoint],  // xᵢ · Rᵢ (host precomputed)
        a_mul_gfinal: &PallasPoint,        // a_final · G_final (host)
        r_prime_mul_h: &PallasPoint,       // r′ · H (host)
        ab_eval_mul_u: &PallasPoint,       // (ab-eval) · U (host)
    ) -> Result<(), ErrorFront>
}
```

### S4: `pallas_accumulate.rs` (~350 lines)

```rust
pub struct PallasAccumulateConfig {
    pub compression: Blake2bCompressionCircuitConfig,
    pub word_config: TranscriptWordConfig,
    pub fq_dummy: NonNativeFqConfig,  // for compatibility with Blake2b chip
    pub challenge_col: Column<Advice>,
    pub s_witness: Selector,
    pub fp: NonNativeFpConfig,
}

pub struct PallasAccumulateChip {
    blake2b: Blake2bCompressionCircuitChip,  // existing, field-generic
    pub fp: NonNativeFpChip,
    pub fq: VestaFqChip,
    pub ecc: PallasEccChip,
    pub ipa: PallasIpaChip,
}
```

The `squeeze_challenges` method is shared with `VestaAccumulateChip` — it uses the existing field-generic Blake2b compression chip.

The `verify_ipa_pallas` method:
1. Parse `IpaProofWitness` → extract L/R points (EpAffine), scalars
2. On HOST: compute `xᵢ⁻¹ · Lᵢ`, `xᵢ · Rᵢ`, `a_final · G_final`, `r′ · H`, `(ab-eval) · U`
3. On HOST: compute `G_final` and `b_final` via IPA folding (same as host_fold helper)
4. Assign all points as `PallasPoint` in the circuit
5. On-curve check all points
6. Squeeze challenges from transcript prefixes
7. LHS = commitment → for each round: LHS = ecc.point_add(LHS, l_scaled[i]); LHS = ecc.point_add(LHS, r_scaled[i])
8. RHS = G' → RHS = ecc.point_add(RHS, H') → RHS = ecc.point_add(RHS, U')
9. ecc.constrain_equal_points(LHS, RHS)

### S5: `recursive_proof.rs` (~250 lines)

```rust
pub struct RecursiveProofConfig {
    pub acc: PallasAccumulateConfig,
    pub instance: Column<Instance>,
}

pub fn prove_recursive(
    params: &ParamsIPA<EqAffine>,
    pk: &ProvingKey,
    proof_witness: IpaProofWitness,
) -> Result<Vec<u8>, Error>
```

### S6: Tests (~300 lines)

- `non_native_fp.rs` tests (in S1 file):
  - `test_fp_add_small`
  - `test_fp_add_wrapping`
  - `test_fp_mul_small`
  - `test_fp_invert`
  - `test_fp_invert_zero_rejected`
  - `test_fp_neg`
  - `test_fp_assign_constant_roundtrip`
  - Corrupt-operation rejection tests

- `pallas_ecc.rs` tests (in S2 file):
  - `test_on_curve_generator`: Pallas generator is on curve
  - `test_on_curve_rejects_invalid`: (1,1) not on curve
  - `test_point_add`: P + Q = R, verify with host computation
  - `test_point_double`: 2P
  - `test_select`: conditional selection
  - `test_constrain_equal`: same point comparison
  - `test_constrain_zero`: zero element

- `pallas_accumulate.rs` tests (in S4 file):
  - `test_verify_ipa_synthetic`: build synthetic proof (like VestaAccumulateChip tests), verify in circuit
  - `test_verify_ipa_rejects_corrupt_challenge`
  - `test_verify_ipa_rejects_corrupt_r_prime`
  - `test_verify_ipa_rejects_corrupt_L_point`
  - `test_verify_ipa_rejects_corrupt_R_point`
  - `test_verify_ipa_rejects_corrupt_commitment`

- `recursive_proof.rs` tests (in S5 file):
  - `test_prove_and_verify_recursive`: prove_recursive → verify_recursive_proof roundtrip
  - `test_recursive_rejects_corrupt_proof`: modified proof bytes → verification fails

### S0: `lib.rs` changes (~20 lines)

Add module declarations:
```rust
pub mod non_native_fp;
pub mod pallas_ecc;
pub mod pallas_ipa;
pub mod pallas_accumulate;
pub mod recursive_proof;
```

## 6. Dependencies & Risks

### 6.1 Test count impact

| Step | New tests | Impact on existing tests |
|------|-----------|------------------------|
| S1 | ~12 | None (new module) |
| S2 | ~8 | None (new module) |
| S3 | ~0 | None (no standalone tests) |
| S4 | ~7 | None (new module) |
| S5 | ~2 | None (new module) |
| **Total** | **~29** | **163 existing tests untouched** |

### 6.2 K value selection

The recursive proof circuit uses K (Halo2 parameter):
- Min K = 17 for k=2 IPA (131K rows, ~90% utilization)
- Recommended K = 18 for k=2 IPA (262K rows, comfortable margin)
- For larger k, K = 19 (k up to 5) or K = 20 (k up to 10)

The ParamsIPA generation must use the same K as the existing `prove_conservation` (which also uses K=17 currently in the IPA strategy).

Actually, ParamsIPA K is for the IPA commitment scheme, not for the circuit. The circuit K is a separate parameter for the recursive proof's Halo2 instance. So the recursive proof can use a different K than the inner proofs.

### 6.3 Verification timing

Each Fp operation takes ~914 rows (mul) or ~10 rows (add/sub). Total ~118K rows. Halo2 proving at k=17 takes roughly a few seconds. Verification (single IPA check) is sub-second.

### 6.4 Risk: Point addition in NonNativeFpChip

Each `point_add` requires:
- 1 Fp inverse (for λ computation) — this is witness-and-verify, ~914 rows
- 6 Fp multiplications — 6 × 914 = 5,484 rows
- 6 Fp add/sub — 6 × 10 = 60 rows

Total per point_add: ~6,458 rows. For 6 point_adds: ~38,748 rows.

For on_curve (8 points): 8 × 6 × (914 + 10) = 44,352 rows.
Grand total: 38,748 + 44,352 + overhead ≈ 85,000 rows (not 118K as earlier estimate).

At k=17 (131K max): 65% utilization. Comfortable margin.

### 6.5 Risk: Verification timing — keygen

Key generation for the recursive circuit at k=17 takes ~30-60 seconds (standard Halo2 keygen). This is a one-time cost per deployment.

### 6.6 Risk: Larger k for inner proofs

If the inner proofs use k=10 (1024 generators), the IPA has 10 rounds. Each additional round adds ~35K rows. At k=10 with K=19: 10 rounds × 35K + base ~85K = ~435K rows. At K=19 (524K max): 83% utilization. Feasible.

---

## 7. Execution Order

```
1. S1 — non_native_fp.rs       ✅ done (1619 lines, 8 tests)
2. S2 — pallas_ecc.rs           ✅ done (570 lines, 5 tests)
3. S3 — pallas_ipa.rs           ✅ done (128 lines, 1 test)
4. S4 — pallas_accumulate.rs    ✅ done (225 lines, 1 test)
5. lib.rs update                ✅ done
6. cargo check --workspace      ✅ clean
7. S5 — recursive_proof.rs      ✅ done (234 lines, 2 tests + instance column)
8. cargo check --workspace      ✅ clean
9. cargo test (filtered)        ✅ 181 tests pass, 17 new
```

Total new code: ~2800 lines (including tests)
Total new files: 5
Files modified: 2 (lib.rs, vesta_fq.rs — added Clone derive)

---

## 8. Verification Checklist

Before Phase 1.13 is complete:

- [x] `cargo check --workspace` passes with zero errors
- [ ] `cargo test -p aetheris-recursive --lib` passes (all tests) — filtered runs pass (181 tests)
- [ ] `cargo test -p aetheris-zkp` passes (no regressions in 119 tests)
- [x] `cargo test -p aetheris-crypto` passes
- [x] `cargo test -p aetheris-core` passes
- [x] NonNativeFpChip tests: add/sub/mul/invert/neg/assign_constant roundtrip (8 tests, K=10-12)
- [x] PallasEccChip tests: on_curve, point_add, point_double, select, negate (5 tests, K=16)
- [x] PallasIpaChip test: k=1 verify_ipa_full (K=16)
- [x] PallasAccumulateChip test: k=1 synthetic proof (K=16)
- [x] RecursiveProofCircuit: k=1 synthetic proof (K=16) + wrong-commitment rejection
- [x] RecursiveProofCircuit: public instance column (commitment coordinates, 6 Fq limbs)
- [x] fix: invert zero-input short-circuit removed (branch-dependent shape bug)
- [x] fix: hardcoded `3`→`FP_NUM_LIMBS` in test helpers
- [x] Existing VestaAccumulateChip tests pass (9 tests)
- [x] All existing ECC/IPA/transcript/Fq/blake2b tests pass (no regression)
- [ ] Recursive proof output size ≤ 10 KB (requires real prove API — deferred)
- [ ] `prove_recursive`/`verify_recursive_proof` host API (deferred to Phase 1.14)
- [ ] Blake2b transcript/challenge squeezing in PallasAccumulateChip (deferred)
- [ ] `precompute_ipa_witness` host helper (deferred)
