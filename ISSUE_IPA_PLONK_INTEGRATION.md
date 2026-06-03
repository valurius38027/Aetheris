# Issue: IPA Commitment Scheme Fails in Plonk Multiopen Verification

## Summary

The IPA (Inner Product Argument) commitment scheme integration with the PSE
halo2 fork's plonk protocol produces proofs that fail verification. The error
manifests as `verify_proof_with_strategy` returning `Ok(strategy)` but
`strategy.finalize()` returning `false` — meaning the plonk constraint system
checks pass, but the **IPA opening proof is invalid**.

## Reproduction

```bash
cargo test --package aetheris-zkp
```

8 of 37 tests fail (all conservation proof roundtrip tests):

- `test_conservation_basic`
- `test_conservation_negative_public_amount`
- `test_conservation_public_amount_net_zero`
- `test_large_value_roundtrip`
- `test_full_conservation_with_commitments_binding`
- `test_aggregate_multi_tx_roundtrip`
- `test_aggregate_with_commitments_binding`
- `test_aggregate_rejects_tampered`

The 29 passing tests include IPA unit tests (roundtrip, serialization, MSM)
and unrelated crypto tests (encrypt/decrypt, VDF). The IPA primitive itself
works; the integration with plonk does not.

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

All other h_eval-related changes (vanishing prover/verifier transcript
writes) were unnecessary and have been excluded.

## Root Cause Analysis

The error path is:

```
verify_proof_with_strategy(...) → Ok(strategy)
strategy.finalize() → false   ← opening proof fails here
```

This means:

1. The constraint system is correctly satisfied (instance columns match,
   gate expressions evaluate to zero).
2. The polynomial commitments are correctly deserialized and read.
3. **But the multi-point opening proof (IPA) does not verify** — the
   combined MSM does not sum to the identity point.

### Likely Causes

**A. Transcript ordering mismatch between prover and verifier.**

The IPA protocol writes `k`, `theta`, then `L_i, R_i, x_i` for each round,
then `a_final`. The plonk protocol intersperses its own transcript
operations. If the ordering between plonk's challenge squeezes and IPA's
transcript reads/writes is inconsistent, the challenges will differ.

**B. Query evaluation mismatch.**

The prover evaluates each polynomial at `x` using
`eval_polynomial(poly, x)` internally. The verifier receives the evaluation
from the plonk verifier (computed via Lagrange interpolation from expressed
constraints). If these differ (even by a constant factor), the IPA check
fails.

**C. Commitment MSM construction.**

The prover commits to h(X) pieces using the generator base; the verifier
rebuilds the combined commitment MSM from the individual h commitments and
the `xn` scaling factor. Any mismatch in the `scale()` direction or the
order of fold produces an incorrect combined commitment.

### What Does Work

- `test_single_strategy_roundtrip` (IPA open + verify in isolation): **PASSES**
- `test_msm_basic` (MSM evaluation): **PASSES**
- `test_params_ipa_serialization_roundtrip` (serialization): **PASSES**

The IPA scheme itself is correct for single-query scenarios. The failure
only occurs with **multiple queries** at the same point `x` (h_poly + random_poly),
which is the multiopen path triggered by the plonk protocol.

## Required Fixes

### Short-Term (Debugging)

1. **Add transcript tracing.** Log all scalars and points written/read by
   both prover and verifier for a single failing test, then compare byte-
   by-byte. This will reveal ordering or value mismatches.

2. **Isolate the multiopen theta folding.** Verify that the combined
   commitment `P = h_commit + theta * random_commit` and combined evaluation
   `e = h_eval + theta * random_eval` used by the prover match exactly what
   the verifier reconstructs.

### Medium-Term (Code)

3. **Fix transcript ordering.** If the prover writes data in a different
   order than the verifier reads it, adjust the IPA
   `create_proof_with_engine` or `verify_proof` to match the halo2
   `VerifierQuery` iteration order.

4. **Verify commitment reference handling.** The `VerifierQuery` enum has
   `CommitmentReference::Commitment` and `CommitmentReference::MSM` variants.
   The h_poly uses `MSM` (because it's a linear combination of multiple h
   piece commitments), while the random_poly uses `Commitment` (single
   commitment). Ensure both variants are handled correctly.

## Workaround

None currently. The IPA scheme cannot be used with the PSE plonk protocol
until the multiopen integration is fixed. KZG (the default) works as a
fallback.

## Files

| File | Role |
|------|------|
| `aetheris-zkp/src/ipa/commitment.rs` | `CommitmentSchemeIPA`, `ParamsIPA`, `MSMIPA` |
| `aetheris-zkp/src/ipa/prover.rs` | `ProverIPA` — IPA prover impl |
| `aetheris-zkp/src/ipa/verifier.rs` | `VerifierIPA` — IPA verifier impl |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/poly.rs` | Visibility patch (pub query) |
| `aetheris-zkp/vendor/halo2/halo2_backend/src/poly/query.rs` | Visibility patch (pub fields) |
| `aetheris-zkp/src/halo2_pasta.rs` | Test harness using IPA |
