# Protocol Closure Progress

Status values:

- `Not Started` — no implementation work has begun.
- `In Progress` — source changes exist or are being prepared.
- `Blocked` — cannot proceed without resolving a prior gate.
- `Ready for Review` — implementation and tests are complete for review.
- `Closed` — acceptance gate and audit step are complete.

## Phase Board

| Phase | Title | Status | Current Gate | Evidence |
| --- | --- | --- | --- | --- |
| 0 | Restore build and evidence baseline | In Progress | Dependency fetch / compile baseline | Workspace manifest now resolves after removing stale `target/check_pkd_temp`; full check is currently blocked by GitHub fetch 403 for the PSE Halo2 git dependency in this environment. |
| 1 | Canonical transaction and note model | Not Started | Core model design approved | Waiting on Phase 0. |
| 2 | ZK transaction circuit closure | Not Started | Commitment/membership/nullifier/value tests pass | Waiting on Phase 1. |
| 3 | Node validation unification | Not Started | Mempool and block validation share one engine | Waiting on Phase 2. |
| 4 | Wallet address/encryption/scan closure | Not Started | Receiver can scan wallet-generated transfer | Waiting on Phases 1-3. |
| 5 | FFI boundary hardening | Not Started | Malformed ABI inputs cannot panic | Can begin after Phase 0; highest safety priority after build fix. |
| 6 | Recursive aggregation trust model closure | Not Started | Aggregation mode documented and tested | Can begin after Phase 0; depends on transaction proof shape for final integration. |
| 7 | End-to-end protocol closure | Not Started | Genesis -> transfer -> block -> scan flow works | Waiting on Phases 1-6. |
| 8 | Post-closure hardening | Not Started | CI/fuzz/property hardening active | Waiting on Phase 7. |

## Acceptance Gate Checklist

### Phase 0 — Restore Build and Evidence Baseline

- [x] Remove or restore missing workspace member.
- [ ] `cargo check --workspace` completes. Current blocker is external dependency fetch, not workspace membership.
- [ ] Safe test matrix recorded.
- [ ] Heavy recursive tests are gated or documented so they are not run by accident.
- [ ] Build/test evidence recorded here.

### Phase 1 — Canonical Transaction and Note Model

- [ ] Consensus-visible transaction fields are defined.
- [ ] Wallet-private witness fields are separated.
- [ ] Proof versioning is represented.
- [ ] Serialization round trips are tested.
- [ ] Node can decide validity from transaction bytes plus chain state.

### Phase 2 — ZK Transaction Circuit Closure

- [ ] Output commitments are circuit-bound to private witness data.
- [ ] Nullifiers are circuit-bound to consumed notes and keys.
- [ ] Membership is circuit-bound to an accepted root.
- [ ] Value balance is circuit-bound to public amount/fee semantics.
- [ ] Malformed proof inputs return errors, not panics.
- [ ] Negative tamper suite passes.

### Phase 3 — Node Validation and State Transition Unification

- [ ] One transaction validation function is used by mempool and blocks.
- [ ] Genesis identity policy is implemented.
- [ ] State root, nullifier, commitment, VDF, and aggregate checks are ordered
      before mutation.
- [ ] Replay from genesis is deterministic.
- [ ] Double-spend and tamper integration tests pass.

### Phase 4 — Wallet Address, Encryption, and Scan Closure

- [ ] Address and key derivation format is implemented.
- [ ] Recipient is actually used by send.
- [ ] Ephemeral keys are random and format-valid.
- [ ] Wallet encryption and scan use the same authenticated format.
- [ ] Dev JSON handoff is disabled by default or feature-gated.
- [ ] Sender/receiver/unrelated-wallet scan tests pass.

### Phase 5 — FFI Boundary Hardening

- [ ] All exported functions are inventoried.
- [ ] Pointer/length/ownership contracts are documented.
- [ ] Every entrypoint contains panic containment.
- [ ] FFI paths do not use unchecked `unwrap`/`expect`.
- [ ] Unsafe blocks have local safety comments.
- [ ] Null/invalid/short/repeated-init tests pass.

### Phase 6 — Recursive Aggregation and Trust Model Closure

- [ ] Proof-core and manager/stub surfaces are separated or clearly marked.
- [ ] Aggregation modes are documented.
- [ ] Trusted aggregator configuration cannot silently downgrade verification.
- [ ] Full replay and trusted fast path tests are present.
- [ ] Node aggregate verification behavior is deterministic.

### Phase 7 — End-to-End Protocol Closure

- [ ] Deterministic dev genesis starts a clean node.
- [ ] Wallet creates a valid shielded transfer.
- [ ] Node accepts transaction into mempool.
- [ ] Block including transfer validates from empty DB.
- [ ] Receiver scans output; sender scans change.
- [ ] Replay produces identical roots and nullifier set.
- [ ] Full-flow tamper suite passes.

### Phase 8 — Post-Closure Hardening

- [ ] VDF difficulty is calibrated.
- [ ] CI matrix separates heavy tests.
- [ ] Parser/proof/FFI fuzzing exists.
- [ ] State transition property tests exist.
- [ ] Operational key/recovery docs exist.

## Evidence Log

| Date | Phase | Evidence | Result |
| --- | --- | --- | --- |
| 2026-07-03 | Baseline | `cargo check --workspace` | Failed at manifest load because `target/check_pkd_temp` is listed but missing. |
| 2026-07-03 | Phase 0 | Workspace member cleanup | Removed stale `target/check_pkd_temp` from workspace members. |
| 2026-07-03 | Phase 0 | `cargo metadata --no-deps --format-version 1` | Passed; workspace manifest resolves and enumerates all intended workspace members. |
| 2026-07-03 | Phase 0 | `cargo check --workspace` | Blocked by environment/dependency fetch: Cargo cannot fetch `https://github.com/privacy-scaling-explorations/halo2.git` due to CONNECT tunnel HTTP 403. |
| 2026-07-03 | Phase 0 | `CARGO_NET_GIT_FETCH_WITH_CLI=true cargo check --workspace` | Same environment blocker: git fetch from GitHub returns CONNECT tunnel HTTP 403. |
| 2026-07-03 | Baseline | Source audit | Identified build, transaction, wallet, node, recursive, and FFI closure gaps. |
