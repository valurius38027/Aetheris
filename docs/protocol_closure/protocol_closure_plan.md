# Protocol Closure Plan

## Baseline: Audited Current State

The current repository should be treated as a prototype with real components but
without a closed protocol boundary. The most important observed facts are:

- The workspace is not currently resolvable because `Cargo.toml` lists a missing
  `target/check_pkd_temp` workspace member.
- The transaction proof story is incomplete: value conservation, output
  commitments, membership, nullifiers, and spend authorization are not yet tied
  into one node-enforced validity path.
- Wallet send/scan still contains prototype behavior: ignored recipient, fixed
  ephemeral keys, ad-hoc ciphertexts, and local JSON handoff files.
- FFI and recursive manager surfaces contain panic and raw-pointer risks.
- Recursive aggregation has useful lower-level pieces, but production trust
  boundaries and stub surfaces are not cleanly separated.

The plan below does not assume legacy roadmap claims are true. Every phase starts
from source-level verification.

## Definitions

### Initial Protocol Closure

Aetheris reaches initial protocol closure when a normal shielded transfer can be
created by the wallet, accepted by the mempool, included in a block, validated by
a node from genesis, and scanned by the receiver, while all externally exposed
interfaces have defined failure behavior.

### Required Security Invariants

- **No phantom spend**: every consumed note is proven to exist in the committed
  note tree at an accepted root.
- **No double spend**: every accepted nullifier is unique and is bound to the
  consumed note and spending key.
- **No value inflation**: private inputs, private outputs, fees/public amounts,
  and issuance rules balance under node verification.
- **No commitment substitution**: output commitments are proven to encode the
  exact private amount, asset, owner, and blinding committed by the transaction.
- **No recipient ambiguity**: the receiver can scan and decrypt outputs using the
  documented address/viewing-key format; unrelated wallets cannot.
- **No verifier mismatch**: mempool, block validation, FFI submission, and tests
  call the same validity logic.
- **No accidental trust downgrade**: any trusted aggregator shortcut is explicit,
  configurable, auditable, and has a full-verification fallback.
- **No FFI panic/UB contract gaps**: exported ABI functions specify and enforce
  pointer, length, ownership, and error behavior.

## Phase 0 — Restore Build and Evidence Baseline

**Goal:** Make the repository mechanically checkable before changing protocol
logic.

**Boundary:** Cargo workspace, dependency resolution, lightweight tests, heavy
test classification.

**Tasks:**

- P0.1 Remove or restore the missing workspace member `target/check_pkd_temp`.
- P0.2 Run `cargo check --workspace` and record all warnings/errors.
- P0.3 Define a safe test matrix:
  - core and crypto: normal package tests;
  - zkp: package tests with bounded threads;
  - ffi: lib tests with one thread;
  - recursive: prefix-filtered light tests only by default.
- P0.4 Mark or gate K=17/K=18 recursive tests so accidental full test runs do
  not OOM developer or CI machines.
- P0.5 Add a short `docs/protocol_closure/checks.md` only if the commands become
  too long for this plan.

**Acceptance Gate:**

- `cargo check --workspace` completes.
- Safe test commands are documented and at least core/crypto pass.
- Heavy recursive tests are discoverable and not part of default local flow.

**Audit Step:**

- Confirm no build artifact path is listed as a workspace member.
- Confirm no test command requires running all recursive tests at once.

## Phase 1 — Define Canonical Transaction and Note Model

**Goal:** Replace implicit transaction assumptions with a single canonical model
that all crates can share.

**Boundary:** `aetheris-core` transaction/note types and serialization.

**Tasks:**

- P1.1 Define canonical note fields: amount, asset id, owner/viewing data,
  randomness/blinding, nullifier key material, and memo/encryption payload.
- P1.2 Split consensus-visible data from wallet-private witness data.
- P1.3 Define transaction public fields:
  - input nullifiers;
  - output commitments;
  - encrypted output payloads;
  - value balance / fee / public amount;
  - note tree root;
  - proof bytes;
  - proof system version.
- P1.4 Define binary and JSON compatibility rules for FFI and wallet surfaces.
- P1.5 Add round-trip tests for canonical serialization.

**Acceptance Gate:**

- Core types express all fields needed by node validation without relying on
  out-of-band wallet state.
- Old prototype fields are either migrated, feature-gated, or explicitly marked
  dev-only.

**Audit Step:**

- Review whether a verifier can decide transaction validity from transaction
  bytes plus current chain state.

## Phase 2 — Close the ZK Transaction Circuit Boundary

**Goal:** Ensure the proof enforces all transaction invariants required by the
node.

**Boundary:** ZKP circuits, proof API, verifier API, negative tests.

**Tasks:**

- P2.1 Bind output commitments to private output amount, asset id, owner data,
  and blinding inside the circuit.
- P2.2 Bind nullifier to consumed note and spending/nullifier key material.
- P2.3 Bind consumed note membership to an accepted Merkle root.
- P2.4 Bind public value balance / fee / issuance semantics to the transaction.
- P2.5 Version proof bytes and reject legacy simulated/stub formats.
- P2.6 Convert public proving APIs from panic/expect behavior to `Result`.
- P2.7 Add negative tests:
  - swapped output commitment fails;
  - wrong Merkle path fails;
  - wrong nullifier fails;
  - wrong public amount fails;
  - non-canonical field bytes return errors, not panics;
  - old simulated prefixes are rejected.

**Acceptance Gate:**

- A valid transfer proof verifies.
- Each single-field tamper case fails.
- Public APIs return structured errors for malformed inputs.

**Audit Step:**

- Independently trace every public transaction byte to either a circuit public
  input, node validation rule, or explicitly non-consensus metadata.

## Phase 3 — Node Validation and State Transition Unification

**Goal:** Make mempool and block validation use one transaction validity engine.

**Boundary:** `aetheris-node` state, mempool, consensus, genesis, issuance, VDF.

**Tasks:**

- P3.1 Implement a single `validate_transaction_against_state` path.
- P3.2 Use the same path for mempool admission and block application.
- P3.3 Enforce note root availability and nullifier uniqueness atomically.
- P3.4 Decide and implement genesis identity policy:
  - strict network identity hash, or
  - explicit configurable dev genesis.
- P3.5 Convert DB open and time errors into `Result` errors, not panics.
- P3.6 Add integration tests:
  - valid genesis + one spend + scanable output;
  - double spend rejected;
  - wrong state root rejected;
  - wrong VDF proof rejected;
  - wrong aggregate proof rejected;
  - mempool accepts exactly what block validation accepts.

**Acceptance Gate:**

- A node can replay from genesis and deterministically reach the same state root.
- Mempool and block validation cannot disagree on transaction validity.

**Audit Step:**

- Review all places that insert nullifiers, commitments, blocks, and state roots;
  confirm validation precedes mutation and persistence ordering is intentional.

## Phase 4 — Wallet Address, Encryption, and Scan Closure

**Goal:** Make wallet-generated transactions match node and ZKP expectations and
make receiver scan reliable.

**Boundary:** `aetheris-wallet`, FFI wallet paths, output encryption format.

**Tasks:**

- P4.1 Define address format and viewing/spending/nullifier key derivation.
- P4.2 Replace ignored recipient behavior with real recipient parsing.
- P4.3 Replace fixed ephemeral keys with generated ephemeral keys.
- P4.4 Replace ad-hoc `AETHSCAN` ciphertext with one authenticated encryption
  format shared by wallet and ZKP helpers.
- P4.5 Add scan boundary checks for truncated ledgers, corrupted ciphertexts,
  and index rollback.
- P4.6 Move wallet logic from CLI-only code into testable library functions.
- P4.7 Add wallet integration tests:
  - generate/import deterministic wallet;
  - send to recipient and scan by recipient;
  - sender change output scans by sender;
  - unrelated wallet cannot decrypt;
  - corrupted ciphertext is ignored or errors safely.

**Acceptance Gate:**

- CLI/FFI wallet can create a transfer that the node accepts and the receiver
  can scan.
- Prototype file handoff is disabled by default or clearly dev-only.

**Audit Step:**

- Review all key material lifetimes, logging, zeroization, and stdout exposure.

## Phase 5 — FFI Boundary Hardening

**Goal:** Make external ABI behavior explicit, non-panicking, and memory-safe
under documented caller obligations.

**Boundary:** `aetheris-ffi` and recursive exported ABI.

**Tasks:**

- P5.1 Inventory every `#[no_mangle] extern "C"` function.
- P5.2 Define pointer/length/nullability/ownership contract for each function.
- P5.3 Wrap every exported entrypoint in panic containment.
- P5.4 Replace `unwrap`/`expect` in FFI paths with error codes and `LAST_ERROR`.
- P5.5 Replace raw manager pointer storage with an ownership-safe wrapper.
- P5.6 Add max input sizes for binary/JSON command buffers.
- P5.7 Add FFI tests for null pointers, invalid UTF-8, short buffers, repeated
  init/free, corrupted JSON, and missing ledger state.

**Acceptance Gate:**

- Malformed FFI input cannot panic across the ABI.
- Ownership and free functions are documented and tested.

**Audit Step:**

- Review each unsafe block and document the local safety invariant beside it.

## Phase 6 — Recursive Aggregation and Trust Model Closure

**Goal:** Make aggregation behavior unambiguous and safe to depend on.

**Boundary:** `aetheris-recursive`, node aggregate verification, FFI recursive
manager surfaces.

**Tasks:**

- P6.1 Separate proof-core APIs from P2P/FFI manager APIs.
- P6.2 Mark stub/unavailable manager paths as non-production or remove them.
- P6.3 Define aggregation modes:
  - full replay verification;
  - trusted signed aggregator fast path;
  - future in-circuit recursive verification.
- P6.4 Define aggregator key governance: configuration, rotation, revocation,
  and fallback.
- P6.5 Add tests that compare full replay and trusted fast path outcomes.
- P6.6 Ensure nodes never silently downgrade from full verification to trusted
  verification without configuration.

**Acceptance Gate:**

- A block aggregate proof can be verified under a documented mode.
- Stub manager APIs cannot be mistaken for production proof generation.

**Audit Step:**

- Threat-model trusted aggregation separately from cryptographic aggregation.

## Phase 7 — End-to-End Protocol Closure

**Goal:** Demonstrate the minimal complete flow.

**Boundary:** all crates through one scenario.

**Tasks:**

- P7.1 Start from deterministic dev genesis.
- P7.2 Generate sender and receiver wallets.
- P7.3 Mine or construct a block containing a valid shielded transfer.
- P7.4 Validate the block from an empty node database.
- P7.5 Scan outputs with sender and receiver wallets.
- P7.6 Replay the chain and compare state roots, balances, nullifiers, and
  commitments.
- P7.7 Run tamper suite against the full flow.

**Acceptance Gate:**

- One documented command sequence demonstrates genesis -> transfer -> block ->
  validation -> scan.
- The same sequence has negative tests for every required security invariant.

**Audit Step:**

- Perform a final boundary review covering transaction, wallet, node, recursive,
  and FFI surfaces before declaring initial closure.

## Phase 8 — Hardening After Initial Closure

**Goal:** Move from initial closure toward production readiness.

**Tasks:**

- H8.1 Calibrate VDF difficulty on target hardware.
- H8.2 Replace local dev genesis with network-specific genesis policy.
- H8.3 Add CI matrix with heavy tests isolated.
- H8.4 Add fuzzing for parsers, FFI buffers, transaction decoding, and proof
  decoding.
- H8.5 Add property tests for state transitions and note tree updates.
- H8.6 Document operational key handling and recovery flows.

**Acceptance Gate:**

- The initial closure flow remains green under CI and fuzz/property test budgets.
