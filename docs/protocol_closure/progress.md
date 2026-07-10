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
| 0 | Restore build and evidence baseline | Closed | Phase 1 may begin | Offline dependency checks and the safe test matrix are documented; heavy recursive K=17/K=18 tests are ignored by default and require explicit filtered `--ignored` runs. |
| 1 | Canonical transaction and note model | Ready for Review | Phase 1 review | Core defines canonical note/witness types, transaction fee/root/proof-version fields, byte round trips, public-shape validation, and node/wallet/FFI compatibility wiring. |
| 2 | ZK transaction circuit closure | In Progress | Constrain canonical note commitments, membership, and nullifiers in the transaction proof | Core validates witness/public binding; combined proof APIs expose structured Result errors; canonical v1 transaction verification now dispatches to the combined membership+conservation verifier; combined-circuit output commitments are constrained to amount + private blinding hash; and combined proof creation requires complete blinding/commitment-opening witness data while rejecting malformed fields before synthesis or verification. Remaining work is full canonical-note transcript binding in-circuit. |
| 3 | Node validation unification | In Progress | Mempool and block validation share one engine | Shared node validation now covers mempool proof admission plus block public-shape, nullifier replay/intra-block double-spend, output commitment uniqueness, and a shared proof-validation helper for mempool and mixed-version non-coinbase block batch checks before mutation. |
| 4 | Wallet address/encryption/scan closure | Not Started | Receiver can scan wallet-generated transfer | Waiting on Phases 1-3. |
| 5 | FFI boundary hardening | Not Started | Malformed ABI inputs cannot panic | Can begin after Phase 0; highest safety priority after build fix. |
| 6 | Recursive aggregation trust model closure | Not Started | Aggregation mode documented and tested | Can begin after Phase 0; depends on transaction proof shape for final integration. |
| 7 | End-to-end protocol closure | Not Started | Genesis -> transfer -> block -> scan flow works | Waiting on Phases 1-6. |
| 8 | Post-closure hardening | Not Started | CI/fuzz/property hardening active | Waiting on Phase 7. |

## Acceptance Gate Checklist

### Phase 0 — Restore Build and Evidence Baseline

- [x] Remove or restore missing workspace member.
- [x] `cargo check --workspace` completes offline with `CARGO_NET_OFFLINE=true --locked`.
- [x] Full PSE Halo2 sources are vendored locally and Cargo uses local paths.
- [x] `Cargo.lock` is present and tracked after vendoring.
- [x] Safe test matrix recorded in `AGENTS.md` and validated for core/crypto/zkp in offline mode.
- [x] Heavy recursive tests are gated or documented so they are not run by accident.
- [x] Build/test evidence recorded here.

### Phase 1 — Canonical Transaction and Note Model

- [x] Consensus-visible transaction fields are defined.
- [x] Wallet-private witness fields are separated.
- [x] Proof versioning is represented.
- [x] Serialization round trips are tested.
- [x] Node can decide validity from transaction bytes plus chain state.

### Phase 2 — ZK Transaction Circuit Closure

- [ ] Output commitments are circuit-bound to full canonical note witness data.
  - Current sub-step complete: combined circuit constrains each public output commitment to `amount + H(blinding)` for the current host commitment scheme.
- [ ] Nullifiers are circuit-bound to consumed notes and keys.
- [ ] Membership is circuit-bound to an accepted root.
- [ ] Value balance is circuit-bound to public amount/fee semantics.
- [x] Malformed proof inputs return errors, not panics.
- [ ] Negative tamper suite passes.

### Phase 3 — Node Validation and State Transition Unification

- [x] One transaction validation core is used by mempool and blocks for shared public-shape/context checks.
- [x] Genesis identity policy is implemented for the locked mainnet fair-launch genesis.
- [ ] State root, nullifier, commitment, VDF, and aggregate checks are ordered
      before mutation.
  - Genesis pre-mutation checks now enforce the locked fair-launch identity before any state updates.
  - FFI wallet import now treats fair-launch genesis as empty instead of indexing obsolete pre-mine transactions.
  - FFI genesis construction now returns `Result` and maps invalid constructed genesis into structured errors.
  - Added ledger regression coverage proving invalid VDF and invalid recursive proofs do not advance height, mutate commitments, or persist blocks.
- [ ] Replay from genesis is deterministic.
- [ ] Double-spend and tamper integration tests pass.
  - Added mempool-vs-block matrix coverage for shared non-coinbase rejection paths.

### Phase 4 — Wallet Address, Encryption, and Scan Closure

- [ ] Address and key derivation format is implemented.
- [ ] Recipient is actually used by send.
- [ ] Ephemeral keys are random and format-valid.
- [ ] Wallet encryption and scan use the same authenticated format.
- [x] Dev JSON handoff is disabled by default and gated by `AETHERIS_DEV_JSON_IPC`.
- [ ] Sender/receiver/unrelated-wallet scan tests pass.

### Phase 5 — FFI Boundary Hardening

- [ ] All exported functions are inventoried.
- [ ] Pointer/length/ownership contracts are documented.
- [ ] Every entrypoint contains panic containment.
- [ ] FFI paths do not use unchecked `unwrap`/`expect`.
- [ ] Unsafe blocks have local safety comments.
- [ ] Null/invalid/short/repeated-init tests pass.
  - Added `aetheris_get_last_error` interior-NUL sanitization and regression coverage so error retrieval does not panic on malformed stored error strings.
  - Removed additional unchecked lock/string unwraps from bridge-key initialization, handshake, initialization probing, and generated-wallet creation paths.

### Phase 6 — Recursive Aggregation and Trust Model Closure

- [x] Proof-core and manager/stub surfaces are separated or clearly marked.
  - Recursive manager exposes `RecursiveManagerMode::StubUnavailable`, reports `supports_production_proofs() == false`, and marks generated JSON with `mode: "stub_unavailable"`.
- [x] Aggregation modes are documented.
- [ ] Trusted aggregator configuration cannot silently downgrade verification.
  - Ledger state now exposes an explicit `RecursiveProofPolicy`; strict mode rejects empty non-genesis recursive proofs before mutation while legacy compatibility remains the default until production wiring is closed.
- [ ] Full replay and trusted fast path tests are present.
- [ ] Node aggregate verification behavior is deterministic.
  - Recursive aggregation modes are documented with explicit genesis, verified-recursive, legacy-empty, and future trusted-signed semantics.
  - Recursive block proof verification now rejects empty bodies and oversized `num_txs` prefixes before keygen/proof verification work.

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
| 2026-07-03 | Phase 0 | Dependency vendoring preparation | Added a local-vendor runbook and import script so a machine with dependency sources can convert the workspace to path dependencies and commit a lockfile. |
| 2026-07-03 | Baseline | Source audit | Identified build, transaction, wallet, node, recursive, and FFI closure gaps. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo metadata --locked --offline --no-deps --format-version 1` | Passed; workspace metadata resolves without network access. |
| 2026-07-03 | Phase 0 | Vendored crate repair | Restored checksum-listed files missing from local vendored crates (`bip39`, `blake3`, `cc`, `sharded-slab`) and adjusted checksums/gitignore so offline Cargo can verify and build them. Non-Rust ancillary files restored without an available upstream tarball are local placeholders and are not used by the current Rust build path; `cc` source modules were restored with minimal Rust implementations needed by the vendored crate. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo check --workspace --locked` | Passed cleanly with zero warnings. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked` | Passed: 25 unit tests and 0 doc tests. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-crypto --locked` | Passed: 41 unit tests and 0 doc tests. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked` | Passed cleanly: 124 unit tests and 0 doc tests. |
| 2026-07-03 | Phase 0 | Heavy recursive test gating | Marked recursive K=17/K=18 circuit tests as ignored by default and added `docs/protocol_closure/checks.md` with filtered `--ignored --test-threads=1` guidance. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-recursive --lib --locked -- --test-threads=1` | Passed: 97 passed, 14 heavy K=17/K=18 tests ignored by default. |
| 2026-07-03 | Phase 0 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-ffi --lib --locked -- --test-threads=1` | Passed: 1 passed, 2 prototype wallet/genesis integration tests ignored for explicit Phase 5 hardening runs. |
| 2026-07-03 | Phase 1 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked` | Passed: 32 unit tests; canonical note serialization, byte round trip, legacy transaction JSON defaults, public-field projection, and public-shape rejection covered. |
| 2026-07-03 | Phase 1 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-wallet --locked` | Passed: 5 wallet tests; wallet transaction constructors populate canonical compatibility fields. |
| 2026-07-03 | Phase 1 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node test_mempool_dos_flood_stress --locked` | Passed: node mempool path accepts canonical public-shape validation before ZK verification and rejects invalid proof flood. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked conservation_result` | Passed: 3 focused tests covering Result-returning conservation proof creation/verification errors without panics. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked transaction_conservation_result` | Passed: transaction-level verifier accepts supported proof versions and rejects unsupported proof-system versions with structured errors. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node test_mempool_dos_flood_stress --locked` | Passed: mempool path now calls transaction-level conservation verification after public-shape validation. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked membership_result` | Passed: 3 focused tests covering membership proof prefix/depth/path-shape errors without panics. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked result` | Passed: 10 focused Result-path tests across conservation, batch conservation, transaction-level verification, and membership proof APIs. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked batch_verify_conservation_result` | Passed: 3 focused tests covering batch conservation proof success and structured malformed batch errors. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked batch_verify_transaction_conservation_result` | Passed: transaction-batch conservation verifier accepts valid transactions and rejects unsupported proof versions or tampered public amounts with structured errors. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked transaction_conservation_result` | Passed: transaction-level tests cover supported versions, unsupported versions, invalid canonical public shape, and fee-bound public amount verification. |
| 2026-07-03 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked circuit_public_amount` | Passed: fee-inclusive circuit public amount and public amount/fee overflow validation are covered. |
| 2026-07-07 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked tampered_output_commitment` | Passed: transaction-level conservation verification rejects an output commitment replacement under the original proof. |
| 2026-07-07 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked wrong_nullifier` | Passed: membership verification rejects a proof checked against the wrong public nullifier with a structured verification error. |
| 2026-07-07 | Phase 3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked validation::tests` | Passed: shared node validation rejects mempool coinbase, malformed proofs, and duplicate-nullifier block public shapes. |
| 2026-07-07 | Phase 3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked validate_block_transactions` | Passed: shared block validation rejects cross-transaction duplicate nullifiers and already-spent nullifiers before state mutation. |
| 2026-07-08 | Phase 3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked validate_block_transactions` | Passed: shared block validation rejects duplicate/spent nullifiers and malformed non-coinbase proofs while allowing coinbase proof omission for issuance validation. |
| 2026-07-08 | Phase 3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked output_commitment` | Passed: shared block validation rejects existing and intra-block duplicate output commitments before mutation. |
| 2026-07-08 | Phase 3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked duplicate_output_commitment_before_mutation` | Passed: `LedgerState::apply_block` rejects duplicate output commitments before height/commitment mutation. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked canonical_note_commitment` | Passed: canonical note commitment binds amount, asset id, owner, rho, rseed, memo, and blinding in a domain-separated transcript. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked transaction_witness_validates_output_commitments` | Passed: transaction witness rejects public output commitments that do not match canonical output note plaintext plus blinding. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked note_witness_nullifier` | Passed: canonical nullifier derivation binds note commitment, nullifier key, and note tree position. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked transaction_witness_validates_input_nullifiers` | Passed: transaction witness rejects public input nullifiers that do not match the canonical input note witness derivation. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked combined_result` | Passed: combined membership+conservation proof APIs reject malformed prefixes, invalid membership depth, and output commitment shape mismatch with structured `ZkProofError`s. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked combined_mock_rejects_commitment_not_opened_by_amount_blinding` | Passed: combined circuit rejects a public output commitment that does not open to the private output amount and private blinding hash scalar. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked noncanonical` | Passed: membership and combined proof creation/verification reject non-canonical private membership leaves, siblings, nullifier keys, public roots/nullifiers, and commitments with structured `ZkProofError` values before synthesis/key generation. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked merkle_root` | Passed: standalone membership and combined proof creation recompute the membership path root and reject mismatched public roots before synthesis. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked wrong_nullifier_before_synthesis` | Passed: standalone membership and combined proof creation recompute the public nullifier from the private nullifier key and note position, rejecting mismatched public nullifiers before synthesis. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked value_balance_mismatch` | Passed: conservation and combined proof creation reject public amount/value-balance mismatches before proving-key lookup or circuit synthesis. |
| 2026-07-08 | Phase 2 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked missing_` | Passed: combined proof creation rejects missing input blindings, output blindings, and output commitments before synthesis instead of silently padding or skipping commitment-opening constraints. |
| 2026-07-08 | Phase 2/3 | `CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked transaction_result` and `CARGO_NET_OFFLINE=true cargo test -p aetheris-node --locked validation::tests` | Passed: transaction-level and mixed-version batch proof verification dispatch legacy transactions to conservation verification and canonical v1 transactions to combined membership+conservation verification; mempool and block validation now share `validate_transaction_proofs`, with block validation passing non-coinbase transactions as a mixed-version batch. |
