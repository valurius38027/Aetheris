# Protocol Closure Issue Backlog

This backlog normalizes audit findings into trackable implementation issues. It is
not a bug dump: each issue has a closure condition and a target phase.

Priorities:

- **P0** — blocks build, testing, or any reliable assessment.
- **P1** — can violate core protocol security or ABI safety.
- **P2** — prevents end-to-end closure or creates serious production ambiguity.
- **P3** — hardening, maintainability, or post-closure quality.

## Closed Issues

### PC-001 — P0 — Workspace references missing `target/check_pkd_temp`

**Phase:** 0

**Problem:** Cargo cannot resolve the workspace while a missing target-directory
crate is listed as a member.

**Required Fix:** Remove the stale member or restore a real crate outside
`target/` if it is intentionally part of the workspace.

**Acceptance:** `cargo metadata --no-deps --format-version 1` succeeds and `cargo check --workspace` progresses past workspace manifest parsing. Full compilation remains tracked by Phase 0 because the environment currently cannot fetch the PSE Halo2 git dependency from GitHub.

**Resolution:** Removed the stale `target/check_pkd_temp` workspace member.

---

## Open Issues

### PC-017 — P0 — Workspace depends on live GitHub fetch for protocol dependency

**Phase:** 0

**Problem:** The workspace cannot be built or tested in a network-restricted
environment because `halo2_proofs` is a live git dependency on GitHub. A
floating branch dependency also makes protocol review non-reproducible.

**Required Fix:** Vendor the full PSE Halo2 workspace into the repository,
preserve the existing local Halo2 patch surface (`halo2_backend`,
`halo2_middleware`), rewrite `Cargo.toml` to a local path dependency, and
commit a generated `Cargo.lock`.

> **Note:** `poseidon-circuit` was previously listed as a git dependency but
> is unused (Poseidon is implemented in-tree). It has been removed from
> `Cargo.toml` and does not need to be vendored.

**Acceptance:** `cargo fetch --offline`, `cargo metadata --no-deps`, and
`cargo check --workspace` work without contacting GitHub.

---

### PC-002 — P1 — Output commitments are not proven from transaction witness

**Phase:** 2

**Problem:** The transaction proof path must prove that public output
commitments encode the private output fields. A conservation-only proof is not
sufficient.

**Required Fix:** Reconstruct and constrain output commitments inside the circuit
using the canonical note commitment scheme.

**Acceptance:** Replacing an output commitment while keeping the same proof and
public amount fails verification.

---

### PC-003 — P1 — Membership and spend authorization are not node-enforced as one transaction validity path

**Phase:** 1, 2, 3

**Problem:** Nullifier uniqueness alone does not prove that a consumed note
exists or is spend-authorized.

**Required Fix:** Define transaction fields and proof constraints for note
membership, nullifier derivation, and spend authorization; enforce them in node
validation.

**Acceptance:** A transaction with a random nullifier and no valid note witness is
rejected by mempool and block validation.

---

### PC-004 — P1 — Wallet send ignores recipient and uses prototype output encryption

**Phase:** 4

**Problem:** The send path does not use the recipient address and emits fixed
prototype ephemeral keys/ciphertexts.

**Required Fix:** Implement recipient parsing, real ephemeral key generation, and
a single authenticated output encryption format shared with scan.

**Acceptance:** Receiver can scan a wallet-created output; unrelated wallet
cannot; changing recipient changes decryptability.

---

### PC-005 — P1 — FFI exported functions can panic or rely on unsafe pointer assumptions

**Phase:** 5

**Problem:** Exported FFI functions do not consistently enforce null, length,
UTF-8, ownership, and panic contracts.

**Required Fix:** Inventory and wrap every entrypoint; replace unchecked
`unwrap`/`expect`; add explicit contracts and malformed-input tests.

**Acceptance:** Null pointers, invalid UTF-8, short buffers, corrupted JSON, and
repeated init/free tests return errors without crossing ABI with panic.

---

### PC-006 — P1 — Recursive manager raw pointer lifecycle is unclear

**Phase:** 5, 6

**Problem:** Global recursive manager storage wraps raw pointers and can leak or
mis-handle repeated initialization/free semantics.

**Required Fix:** Define ownership, release old handles on replacement or reject
replacement, and cover with tests.

**Acceptance:** Repeated init/free has deterministic behavior and no leaks or
use-after-free under sanitizer-compatible test strategy.

---

### PC-007 — P1 — Genesis identity policy is inconsistent

**Phase:** 3

**Problem:** The codebase has a locked genesis identity concept, but node
validation appears structural rather than identity-enforcing.

**Required Fix:** Decide strict network genesis versus configurable dev genesis
and implement that policy in node validation.

**Acceptance:** Mainnet-mode nodes reject a structurally valid but identity-wrong
genesis; dev-mode nodes make configurability explicit.

---

### PC-008 — P1 — Genesis accumulator construction can continue after failure

**Phase:** 3, 6

**Problem:** Genesis aggregate construction should fail fast if proof
accumulation fails.

**Required Fix:** Return `Result` from genesis construction and propagate
accumulator errors.

**Acceptance:** Injected accumulator failure prevents genesis block creation and
is reported as a structured error.

---

### PC-009 — P2 — Local JSON wallet/node handoff is treated like production flow

**Phase:** 4

**Problem:** `pending_tx.json` and `ledger_outputs.json` are unauthenticated,
racy local-file channels.

**Required Fix:** Move these paths behind a dev feature or replace them with
authenticated IPC/RPC.

**Acceptance:** Default wallet/node flow does not rely on unauthenticated local
JSON files.

---

### PC-010 — P2 — Node mempool and block validation can diverge

**Phase:** 3

**Problem:** Mempool and block validation must use the same transaction validity
logic to avoid accepting transactions that later fail in blocks or vice versa.

**Required Fix:** Centralize transaction validation and call it from both paths.

**Acceptance:** A shared test matrix proves valid and invalid transactions have
identical outcomes in mempool and block validation.

---

### PC-011 — P2 — ZKP public APIs panic on malformed input or missing params

**Phase:** 2

**Problem:** Public proving/verification helpers should return structured errors
for non-canonical bytes, missing params, or proof creation failures.

**Required Fix:** Introduce `Result`-returning APIs and adapt callers.

**Acceptance:** Malformed roots, nullifiers, commitments, and missing params are
reported without panic in tests.

---

### PC-012 — P2 — Recursive aggregation trust model is ambiguous

**Phase:** 6

**Problem:** Full replay verification, trusted signed aggregation, and future
recursive proof verification have different trust assumptions.

**Required Fix:** Document and enforce explicit aggregation modes.

**Acceptance:** Node configuration determines aggregation mode; tests prove no
silent downgrade from full verification to trusted mode.

---

### PC-013 — P2 — Stub recursive manager surfaces can be mistaken for production support

**Phase:** 6

**Problem:** Manager APIs that return unavailable/stub behavior coexist with real
lower-level accumulator APIs.

**Required Fix:** Remove, rename, feature-gate, or loudly mark non-production
stub surfaces.

**Acceptance:** Production build cannot accidentally call stub proof generation
without receiving a typed unsupported error.

---

### PC-014 — P2 — Heavy recursive tests are easy to run accidentally

**Phase:** 0, 8

**Problem:** K=17/K=18 recursive tests can exhaust memory if run as part of a
naive full test command.

**Required Fix:** Mark heavy tests ignored, feature-gate them, or provide a
separate heavy-test command profile.

**Acceptance:** Default local test instructions cannot run heavy recursive tests
accidentally.

---

### PC-015 — P3 — Wallet mnemonic and key material logging needs review

**Phase:** 4, 8

**Problem:** Wallet generation and debug paths must avoid leaking mnemonic or key
material to stdout/logs except under explicit user-controlled recovery flows.

**Required Fix:** Review and restrict mnemonic/key output; add warnings or
explicit flags where display is unavoidable.

**Acceptance:** Default wallet generation does not leak secrets into logs unless
the user explicitly requests display.

---

### PC-016 — P3 — VDF difficulty needs production calibration

**Phase:** 8

**Problem:** Default VDF difficulty must be calibrated against target hardware and
block-time goals after the protocol path is closed.

**Required Fix:** Benchmark, select network parameters, and document retargeting
assumptions.

**Acceptance:** VDF parameters are justified by reproducible benchmark evidence.

## Closed Issues

None yet. This tracker starts from the 2026-07-03 audit baseline.
