# Issue: IPA Commitment Scheme Fails in Plonk Multiopen Verification

**⚠️ CRITICAL: Phase 1.1.4 "transcript h_eval" fix MUST be removed — it is a
soundness hole, not a fix. See below.**

**Phase 3 update (June 2026)**: The extended-domain aliasing theory is
**DISPROVEN**. The domain.rs fix (`qpd+1`) is retained as a correctness
improvement but does not resolve the quotient mismatch. The real root cause
is a systematic DC artifact in the IFFT output at indices ≥ 4094.

## Summary

The IPA (Inner Product Argument) commitment scheme integration with the PSE
halo2 fork's plonk protocol has a fundamental bug: **the prover's polynomial
f(X) (computed via coset evaluation + FFT) differs from the verifier's
direct expression evaluation at challenge x**.

The identity `f_prover(x) = f_verifier(x)` is mathematically guaranteed by
construction of h(X) = f(X) / (X^n - 1). That it fails reveals a bug in either
the prover's `evaluate_h` (coset path) or the verifier's expression
evaluation.

The Phase 1.1.4 "fix" bypasses the constraint check by using prover-written
`h_eval` directly in the IPA opening, CREATING A SOUNDNESS HOLE (see below).

## Reproduction

```bash
cargo test --package aetheris-zkp
```

**Current state (Phase 1.1.4):** 37/37 tests pass, but the constraint check
(`expected_h_eval == h_eval_from_transcript`) is DISABLED. This is NOT a fix.

**What should happen:** The constraint check must verify that
`h_eval = f(x) / (x^n - 1)`. Currently expected_h_eval (from expressions)
differs from the prover's h_eval (from transcript), so the check fails:

```
[VERIFIER] expected_h_eval=0x3d1c29c8... transcript_h_eval=0x232675a5... match=false
```

Both f(x) values are non-zero and differ:
```
fx_verifier = expected_h_eval * (xn - 1) = 0x29cd0fcf...
fx_prover   = h_eval * (xn - 1)          = 0x2d02f218...
```

## Environment

| Component | Source | Version |
|-----------|--------|---------|
| `aetheris-zkp` | local | 0.1.0 |
| `halo2_backend` | PSE fork (vendor) | 0.4.0 (commit 198e9ae3) |
| `halo2_middleware` | PSE fork (vendor) | 0.4.0 |
| `halo2_proofs` | PSE fork (git) | 0.4.0 |
| `CommitmentSchemeIPA` | `aetheris-zkp/src/ipa/` | local |

## Vendor Changes (Required)

The PSE fork's `halo2_backend` crate uses `pub(crate)` visibility on types
needed by external `CommitmentScheme` implementations. These minimal changes
are vendored in `aetheris-zkp/vendor/halo2/`:

| File | Change | Reason |
|------|--------|--------|
| `poly.rs:17` | `mod query` → `pub mod query` | `VerifierQuery`/`ProverQuery` types must be accessible from outside the crate |
| `poly.rs:28` | `pub(crate) use` → `pub use` | Re-export the query types publicly |
| `poly/query.rs:23-25` | `pub(crate)` → `pub` on fields | IPA prover reads `q.point`, `q.poly` directly |
| `poly/query.rs:92-97` | `pub(crate)` → `pub` on fields | IPA verifier reads `q.point`, `q.eval`, `q.commitment` directly |

## Investigation Findings

### ✅ What Has Been Confirmed Correct

1. **Transcript ordering.** k, theta, L_i, R_i, x_i, a_final all match
   between prover and verifier. The xn values match:
   `xn = 0x2aa93f5ddbaa00b71b5b0b8c112204648a412a0e78f558f161701dc8c38f3a30`
   (both sides identical).

2. **h_poly data flow.** Prover's h_poly has length n=2048 (= params.n()),
   same as the IPA combined vector. The zip in `create_proof_with_engine`
   does NOT truncate (all lengths match).

3. **Commitment MSM reconstruction.** Both prover and verifier use the same
   piece recombination formula: `h_poly = h_0 + xn*h_1 + xn^2*h_2 + ...`.
   The `MSM` variant handling in the IPA verifier correctly clones and
   scales the pre-assembled combined MSM.

4. **IPA multi-query protocol.** `test_multi_query_ipa_roundtrip` (simulated
   PLONK scenario with piece-commitment MSM + random_poly) passes.

5. **Poly lengths.** All polynomials have length n=2048 (k=11). No silent
   truncation.

### ❌ The Real Root Cause: f_prover(x) ≠ f_verifier(x)

The prover computes f(X) via:
1. Evaluate all gate expressions on the **extended coset domain**
   (`evaluate_h` in `evaluation.rs`)
2. `divide_by_vanishing_poly` (pointwise division by X^n-1 on coset)
3. `extended_to_coeff` (iFFT + remove coset shift)
4. Reconstruct h_poly from pieces
5. `h_eval = eval_polynomial(h_poly, x)` → this is `h(x) = f(x)/(x^n-1)`

The verifier computes f(x) directly:
1. Evaluate all gate expressions at **challenge point x** (via
   `gate.poly.evaluate`, `permutation.expressions`, etc.)
2. `expected_h_eval = fold(expressions, y) * (x^n-1)^{-1}`

**The polynomial f(X) should be identical in both paths.** The fact that
f_prover(x) ≠ f_verifier(x) means either the coset FFT path produces a
different polynomial, or the expression evaluation differs.

Debug output confirms f(x) mismatch:
```
fx_verifier = 0x29cd0fcfd0fb31b9da2768904db7cf42caed2764f4738e412dac9c4c7505e61ec
fx_prover   = 0x2d02f2183649153689a5a729848a6f6494d8f056f4ce7a3b5a05c2bf075692a6
```

### Known Facts About the Expression Evaluation

- There are **14 expression values** on the verifier side:
  - 3 custom gates (running_sum, bit_constraint, constrain_equal)
  - ~5 permutation argument expressions
  - ~6 from other built-in constraints (constant enforcement, etc.)
- All 14 are non-zero (expected — individual gates need not vanish at x)
- The y-folding formula is identical on both sides

### Eliminated Hypotheses

| Hypothesis | Status | Reason |
|------------|--------|--------|
| Extended-domain aliasing (extended_k too small) | ❌ **DISPROVEN** | Fix applied (k=13, n=8192); mismatch persists identically |
| Zip truncation in IPA prover | ❌ Eliminated | h_poly len = 2048 = n |
| Theta folding mismatch | ❌ Eliminated | Multi-query IPA test passes |
| xn mismatch | ❌ Eliminated | Both sides identical |
| MSM construction (scale direction) | ❌ Eliminated | Horner formula verified |
| Coset shift (zeta) bug | ❌ Eliminated | IFFT roundtrip verified across all test cases |
| extended_k=13 insufficient (still aliasing) | ❌ **DISPROVEN** | Same DC artifact appears at both 4096 and 8192 points |
| Permutation product eval mismatch | ❓ UNKNOWN | Not yet verified |

### Remaining Suspects (resolved)

1. ✅ **Prover's evaluate_h produces a different polynomial.** The coset FFT
   pipeline (`coeff_to_extended` → evaluate_h → `divide_by_vanishing_poly` →
   `extended_to_coeff` → truncate) was investigated via multiple diagnostics and
   found correct: the h_poly from IFFT reconstructs h_coset faithfully
   (eval_polynomial(h_poly, ZETA) = h_coset[0] verified across all test cases).
   The division check (all 4096 points) passes. The forward-FFT IFFT roundtrip
   is mathematically consistent. **However, the h_poly has SPURIOUS DEGREE**:
   indices 4094+ contain systematic DC offsets that should be zero.

2. ❌ **Expression count/order mismatch.** The prover's `evaluate_h` produces 14
   expressions; the verifier's `expressions` iterator also produces 14. The h-pieces
   commitment count (2) matches `quotient_poly_degree`. **Eliminated.**

3. ❌ **The quotient_poly_degree truncation.** Both prover and verifier use
   `quotient_poly_degree = 2` (from `cs.degree() = 3`). The truncation to
   `n * quotient_poly_degree = 4096` is a no-op (h_poly already has 4096 elements
   after IFFT). No high-degree coefficients are discarded.

### Phase 2 Finding (DISPROVEN — extended domain aliasing is NOT the root cause)

**The extended-domain aliasing theory has been tested and rejected.**

The fix (`while (1 << extended_k) < (n * (quotient_poly_degree + 1))` on
`domain.rs:49`) was applied, producing extended_k=13, extended_n=8192. This
doubles the sampling points from 4096 to 8192, which should fully resolve any
polynomial up to degree 8191 (> 6141). Despite this, **the fx mismatch persists
identically.**

### Phase 3 Discovery: Systematic IFFT DC Artifact

Diagnostics at extended_k=13 (extended_n=8192) reveal:

| Index range | Value |
|-------------|-------|
| h_poly[0..4093] | normal coefficients (non-zero, varying) |
| h_poly[4094] | constant C₁ (same value every run at same challenge) |
| h_poly[4095] | constant C₂ (different from C₁; same every run at same challenge) |
| h_poly[4096..8191] | constant C₁ (repeating pattern of C₁,C₂) |

When extended_k=12 (extended_n=4096), the same pattern appears compressed:

| Index range | Value |
|-------------|-------|
| h_poly[0..4093] | normal coefficients |
| h_poly[4094] | constant C₁ |
| h_poly[4095] | constant C₂ |

**Key observations:**

1. **The constant values C₁, C₂ are the same regardless of extended_n** (4096 or
   8192). They appear at indices 4094+ in both cases. This is NOT aliasing —
   aliasing would produce different values at different sampling rates.

2. **The pattern repeats at 8192**: h_poly[4096..8191] = interleaved C₁,C₂*,
   matching the coset-structure periodicity. This is a DC-to-every-bin artifact
   from the IFFT.

3. **Normal coefficients up to index 4093** are correct (they roundtrip via FFT
   back to h_coset). The error is isolated to indices ≥ 4094.

### The Mismatch Mechanism (Updated)

```
h_true(X) = degree 4093 (theoretical)
h_poly(X) = degree 4095 (actual IFFT output — spurious DC at 4094+)

At random challenge x:
  f_verifier(x) = expression evaluated at x
  f_prover(x)   = h_poly(x) * (x^n - 1)  [includes DC-noise terms]
```

The DC artifact at indices 4094+ is **not a random aliasing product** — it is a
systematic bias introduced during the coset-evaluation-to-IFFT pipeline. The
IFFT of the correctly-computed `h_coset` produces these spurious coefficients,
meaning the `extended_to_coeff` path (IFFT + coset removal) does not correctly
compute the polynomial uniquely determined by the coset evaluations.

### Possible Root Causes (Under Investigation)

1. **`extended_to_coeff` / `distribute_powers_zeta(false)`**: The forward
   transform `coeff_to_extended` distributes the 2048 input coefficients into
   a coset pattern and zero-pads to extended_n, then FFTs. The inverse
   `extended_to_coeff` IFFTs and reverses the distribution. When
   `extended_k > k`, the distribution pattern's phase mismatch between
   the 2048-signal space and the 8192-FFT space may leave DC residuals.
   *Action*: Verify roundtrip with a synthetic polynomial of known degree 4093.

2. **Expression folding introduces unaccounted high-degree terms**: The 14
   expressions (3 gates + ~11 permutation/constraint) may produce a coset
   evaluation `f_coset` that corresponds to polynomial of degree > 4095,
   even though individual expression degrees sum to 6141. The coset evaluations
   at 8192 points are correct, but the IFFT assumes a degree ≤ 8191
   polynomial — which may itself produce a spurious DC if the evaluations
   come from a degree > 8191 polynomial.
   *Action*: Verify by evaluating the 8192 coset points of a synthetic
   degree-6141 polynomial and checking IFFT roundtrip.

3. **`divide_by_vanishing_poly` normalization error**: The division
   `h_coset[i] = f_coset[i] * t_evaluations[i % (extended_n/n)]` works
   pointwise on the coset. If any `f_coset[i]` is not a multiple of
   `(X^n - 1)` at that point (due to numerical precision or domain mismatch),
   the division introduces a spurious polynomial that is not degree-bounded.
   *Action*: Verify by computing `f_coset[i] / (x_i^n - 1)` directly for
   a random subset and comparing to `h_coset[i]`.

### Why KZG Works But IPA Fails

Both schemes use **identical prover/verifier code** and the same domain parameters
(PROVING_K=11, n=2048). The difference is:

- **KZG (`verify_proof_multi`)**: The verifier check at
  `vanishing/verifier.rs:130-132` (`expected_h_eval != h_eval_from_transcript`)
  was previously **disabled** (Phase 1.1.4 bypass). The KZG tests may still pass
  because the constraint check error is caught and discarded by the
  `verify_proof_multi` wrapper (`Err(_) => false`), while the actual opening
  verification (KZG pairing check) succeeds despite the constraint mismatch.
  
  **UPDATE**: The constraint check was re-enabled (currently active) — see
  `vanishing/verifier.rs:130-132`. Both KZG and IPA now go through this check.
  If KZG tests still pass, the error must be handled differently in the
  verification flow, or the constraint check produces the correct result for
  KZG (unlikely given same prover code).

- **IPA (`verify_proof_with_strategy`)**: Returns `Errr(Error::ConstraintSystemFailure)`,
  causing `verify_conservation` to return `false`. The IPA test
  `test_valid_proof_is_rejected_until_ipa_plonk_quotient_mismatch_is_fixed`
  EXPECTS failure — so the constraint violation is the intended test outcome.

### Previous Hypotheses (Status Update)

| Hypothesis | Status | Evidence |
|------------|--------|----------|
| Zip truncation in IPA prover | ❌ Eliminated (Phase 1) | h_poly len = 2048 = n per `[PROVER]` output |
| Theta folding mismatch | ❌ Eliminated (Phase 1) | Multi-query IPA test passes |
| xn mismatch | ❌ Eliminated (Phase 1) | `[PROVER]` shows xn, matches verifier |
| Coset shift (zeta) bug | ❌ Eliminated (Phase 2) | IFFT roundtrip verified across ALL test cases |
| Extended domain size insufficient for f_true degree | ❌ **DISPROVEN (Phase 3)** | extended_k=13 (8192 pts) produces SAME DC artifact as extended_k=12 (4096 pts) |
| Expression degree underestimation | ❓ UNKNOWN (Phase 3) | Possible hidden high-degree terms from permutation main constraint; needs investigation |

## Diagnostic Traces

The following diagnostics have been placed in `vanishing/prover.rs` and `prover.rs`
and remain in the codebase:

| Diagnostic | Location | Purpose |
|------------|----------|---------|
| `[IFFT-ERR]` | `vanishing/prover.rs:construct()` | Asserts h_poly(ZETA) == h_coset[0] post-IFFT |
| `[fx-MISMATCH]` | `vanishing/prover.rs:evaluate()` | Compares f_prover(x) to f_direct(x) — prints only on mismatch |
| `[VERIFIER] expected_h_eval != transcript_h_eval` | `vanishing/verifier.rs:verify()` | Constraint check returning `Err(ConstraintSystemFailure)` |

## Current State

- **Diagnostics cleaned up** — `[fx-MISMATCH]` diagnostic retained in
  `vanishing/prover.rs`. All other temporary diagnostics removed.
- **Constraint check re-enabled** — `vanishing/verifier.rs:130-132` returns
  `Err(ConstraintSystemFailure)` when mismatch detected.
- **Configuration**: k=11, n=2048, **extended_k=13 (fixed via qpd+1)**, extended_n=8192,
  qpd=2, cs.degree()=3.
- **Circuit**: `ValueConservationCircuit` — 3 advice, 1 instance, 2 selectors,
  bit_constraint gate (deg 3), running_sum gate (deg 2), constrain_equal gate (deg 2).
- **Blinding factors**: 5.
- **Permutation**: 4 columns, chunk_len=1, 4 sets.
- **Domain fix retained**: `domain.rs:49` uses `qpd+1`, giving extended_k=13. This
  is a correctness improvement per protocol_design_ruling.md, even though it does
  not resolve the IPA mismatch.

## Required Fix (Updated — Phase 3)

**The domain-size aliasing theory has been DISPROVEN.** The extended_k=13 fix
(`domain.rs:49` with `qpd+1`) is retained as a correctness improvement but does
NOT resolve the mismatch.

### The Real Problem

The IFFT of the correctly-computed coset evaluations produces h_poly with
**systematic non-zero coefficients at indices ≥ 4094**. These appear as a
constant DC-like artifact regardless of extended domain size (4096 or 8192).

This means the `extended_to_coeff` pipeline does NOT produce the unique
polynomial of degree ≤ 4093 that matches the coset evaluations. Instead,
it produces a degree-4095 polynomial with spurious trailing terms.

### Next Investigation Steps

1. **Synthetic roundtrip test**: Create a known polynomial of degree 4093.
   Simulate `coeff_to_extended` → `evaluate_h` (just eval at coset points) →
   `divide_by_vanishing_poly` → `extended_to_coeff`. Verify that the original
   polynomial is recovered. If not, the bug is in the FFT/coset pipeline
   independent of the circuit.

2. **Check `distribute_powers_zeta` roundtrip**: The forward transform uses
   `distribute_powers_zeta(true)` on the coefficient domain (n=2048) then
   FFTs. The inverse IFFTs then uses `distribute_powers_zeta(false)` on the
   full extended domain. Verify the phase factors are correct when
   `extended_k > k`.

3. **Verify `divide_by_vanishing_poly` produces a polynomial**: For each
   coset point, `h_coset[i] * (x_i^n - 1) - f_coset[i]` should be zero.
   Already verified. But check whether `h_coset` itself comes from a
   polynomial of degree ≤ n*qpd-1 = 4095 — and whether the IFFT of h_coset
   should produce zero at indices ≥ 4094 (it theoretically should if h has
   degree ≤ 4093).

4. **Expression degree inflation**: Check whether any expression (permutation
   main constraint in particular) introduces terms that raise the effective
   degree of f_true beyond 6141 in the coset domain. The coset shift may
   cause cross-term multiplication that is not accounted for.

### What Has Been Eliminated

| Fix | Result |
|-----|--------|
| extended_k=13 (qpd+1) | ❌ Mismatch persists |
| Blinding factors truncation | ❌ Not the cause (no truncation occurs) |
| Transcript ordering | ❌ Symmetric verified |
| Expression count mismatch | ❌ Both sides produce 14 expressions |
| IFFT roundtrip | ❌ h_poly(ZETA) == h_coset[0] verified, but h_poly has spurious degree |

## Files

| File | Role |
|------|------|
| `aetheris-zkp/src/ipa/commitment.rs` | `CommitmentSchemeIPA`, `ParamsIPA`, `MSMIPA` |
| `aetheris-zkp/src/ipa/prover.rs` | `ProverIPA` — IPA prover impl |
| `aetheris-zkp/src/ipa/verifier.rs` | `VerifierIPA` — IPA verifier impl |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/poly.rs` | Visibility patch (pub query) |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/poly/query.rs` | Visibility patch (pub fields) |
| `aetheris-zkp/src/halo2_pasta.rs` | Test harness using IPA |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/vanishing/prover.rs` | Prover's h_poly construction and h_eval write |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/vanishing/verifier.rs` | Verifier's expected_h_eval computation |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/evaluation.rs` | Prover's evaluate_h — coset-domain f(X) computation |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/plonk/prover.rs` | fx_direct computation (duplicate of verifier expression eval)
