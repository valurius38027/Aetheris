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

**Resolution:** Cargo uses local path/vendor sources and offline locked metadata/checks pass without contacting GitHub.

---

## Open Issues

### PC-002 — P1 — Output commitments are not proven from transaction witness

**Phase:** 2

**Problem:** The transaction proof path must prove that public output
commitments encode the private output fields. A conservation-only proof is not
sufficient.

**Required Fix:** Reconstruct and constrain output commitments inside the circuit
using the canonical note commitment scheme.

**Acceptance:** Replacing an output commitment while keeping the same proof and
public amount fails verification.

**2026-07-07 Evidence:** The transaction-level conservation verifier now has a
focused regression test proving that replacing an output commitment under the
same proof returns `ZkProofError::VerificationError`. Full canonical note
commitment binding for asset/owner fields remains open.

**2026-07-08 Evidence:** `aetheris-core` now defines a domain-separated
canonical note commitment transcript over amount, asset id, owner, rho, rseed,
memo length/content, and commitment blinding. This closes the host-side field
order/spec gap for output commitments, but the circuit still must reproduce and
constrain the same transcript before PC-002 can close.

**2026-07-08 Evidence:** `TransactionWitness` and `OutputNoteWitness` now
separate output private witness data from public transaction outputs, and the
witness validation helper rejects public commitments that do not match canonical
output note plaintext plus blinding. This gives the prover/wallet path a stable
witness/public consistency check while circuit enforcement remains the next
required step.

**2026-07-08 Evidence:** Combined membership+conservation proof entrypoints now
provide `Result` variants for proof creation and verification. Malformed prefixes,
invalid membership depth, and output commitment shape mismatches return structured
`ZkProofError`s instead of panicking or collapsing to ambiguous `false`.

**2026-07-08 Evidence:** Membership and combined proof creation now reject
non-canonical private membership witness field encodings (leaf, path siblings,
and nullifier key) before synthesis. Membership and combined proof creation now
also recompute the Merkle path root before synthesis and reject witnesses whose
path does not match the public root. They additionally recompute the public
nullifier from the private nullifier key and note position before synthesis and
reject mismatched nullifiers with `ZkProofError::MembershipNullifierMismatch`.
Membership and combined verification reject non-canonical public
roots/nullifiers/commitments before key/proof synthesis or verification. This
closes panic-safety, avoidable-work, path/root mismatch, and host-side
nullifier-mismatch gaps before structured proof work begins.

**2026-07-08 Evidence:** `CombinedConservationCircuit` now constrains each
public output commitment to the private output amount and private `H(blinding)`
scalar used by the current host commitment scheme (`cm = amount + H(blinding)`
in Fq). This moves output commitment binding from API-only checks into circuit
constraints for the amount/blinding-hash opening. Full canonical note transcript
binding over asset id, owner, rho, rseed, and memo remains open.

**2026-07-08 Evidence:** Conservation and combined proof creation now
precompute the value-balance equation `sum(inputs) - sum(outputs) ==
public_amount` with `i128` host arithmetic and reject mismatches with
`ZkProofError::ValueBalanceMismatch` before proving-key lookup or synthesis. The
constraint remains enforced in-circuit for cryptographic validity, while the
precheck makes malformed witness/public amount pairs fail deterministically and
cheaply.

**2026-07-08 Evidence:** Combined proof creation now requires complete private
value/commitment-opening witness data: input blindings must match input amounts,
output blindings must match output amounts, and public output commitments must
match output amounts. The combined canonical path no longer silently pads absent
blindings or skips output commitment opening constraints for non-empty outputs.

**2026-07-08 Evidence:** Transaction-level proof verification now dispatches by
`proof_system_version`: legacy transactions use the conservation verifier, while
`PROOF_SYSTEM_CANONICAL_SHIELDED_V1` transactions use the combined
membership+conservation verifier over `note_root`, the public nullifier, output
commitments, and fee-adjusted public amount. Canonical v1 transactions can no
longer be accepted with a legacy conservation-only proof prefix. Mixed-version
batch transaction verification uses the same dispatch path, while the
legacy-conservation batch helper is explicitly legacy-only. Node validation now
routes both mempool proof checks and block non-coinbase batch proof checks
through `validate_transaction_proofs`, after public-shape and
replay/duplicate checks for blocks.

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

**2026-07-07 Evidence:** Membership proof Result-path coverage now rejects a
valid proof when checked against the wrong public nullifier. Node-level unified
membership enforcement remains open for Phase 3.

**2026-07-08 Evidence:** `NoteWitness::nullifier` now derives the canonical
input nullifier from the note commitment, nullifier key, and note tree position.
This closes the host-side nullifier transcript gap, but the transaction circuit
still must constrain the same derivation before random public nullifiers are
cryptographically impossible.

**2026-07-08 Evidence:** `TransactionWitness::validate_public_inputs` now
checks that every consensus-visible input nullifier matches the canonical
nullifier derived from the private input witness. This gives wallet/prover code
a single host-side witness/public binding check for inputs while the ZK circuit
constraint remains open.

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

**Status:** Fixed for the mainnet validation path. Node genesis validation now
enforces the locked fair-launch genesis identity and rejects legacy pre-mine
transactions, wrong state roots, wrong VDF placeholders, wrong difficulty, and
identity-wrong timestamps before state mutation. A future dev-mode override, if
needed, must be explicit rather than falling through the mainnet validator.

**Problem:** The codebase has a locked genesis identity concept, but node
validation appeared structural rather than identity-enforcing.

**Resolution:** Implemented strict `validate_genesis_block` policy in node
validation and wired `LedgerState::apply_block_with_validation` to call it for
height 0. The policy matches the fair-launch `create_genesis_block` shape: zero
parent, empty transaction list, empty state root, current `VDF_DIFFICULTY`, zero
VDF placeholders, empty recursive proof, and `EXPECTED_GENESIS_HASH`. The FFI
wallet import path no longer indexes removed prototype pre-mine transactions and
fails explicitly if genesis construction ever contains unexpected allocations.

**Acceptance:** Mainnet-mode nodes reject a structurally valid but identity-wrong
genesis. Configurable dev genesis remains a separate explicit follow-up rather
than an implicit bypass of the locked mainnet identity.

---

### PC-008 — P1 — Genesis accumulator construction can continue after failure

**Phase:** 3, 6

**Status:** Partially fixed for the fair-launch genesis path. Genesis block
construction now returns `Result` and validates the constructed block against the
locked node-side genesis policy before callers can apply or hash it. Because the
current fair-launch genesis has no recursive aggregate proof, the remaining
Phase 6 work is to add an injectable recursive/accumulator construction failure
once genesis carries a non-empty aggregate.

**Problem:** Genesis aggregate construction should fail fast if proof
accumulation fails.

**Resolution:** `create_genesis_block` now propagates structured construction
errors to FFI callers (`GENESIS_CONSTRUCTION_FAILED`) instead of returning an
unchecked block.

**Acceptance:** Constructed genesis validation failures prevent genesis use and
are reported as structured FFI errors; recursive accumulator fault injection
remains tracked for the first genesis format that actually carries an aggregate.

---

### PC-009 — P2 — Local JSON wallet/node handoff is treated like production flow

**Phase:** 4

**Status:** Fixed for default execution. The wallet and node only use local JSON
file IPC when `AETHERIS_DEV_JSON_IPC=1` (also accepts `true`/`yes`) is set.
Default wallet `net`, `send`, and `scan` commands fail closed instead of reading
or writing unauthenticated `node_status.json`, `pending_tx.json`, or
`ledger_outputs.json`; default node loops skip status export and wallet file
watching.

**Problem:** `pending_tx.json` and `ledger_outputs.json` are unauthenticated,
racy local-file channels.

**Resolution:** Moved these paths behind an explicit dev-only environment gate.
Production/default flows must use authenticated RPC/IPC work tracked in later
Phase 4/7 tasks.

**Acceptance:** Default wallet/node flow does not rely on unauthenticated local
JSON files.

---

### PC-010 — P2 — Node mempool and block validation can diverge

**Phase:** 3

**Status:** Fixed for shared transaction public-shape/proof validation.

**Problem:** Mempool and block validation must use the same transaction validity
logic to avoid accepting transactions that later fail in blocks or vice versa.

**Resolution:** `aetheris-node::validation` now routes mempool and block
transaction admission through one shared public-shape/context validation core,
then applies context-specific policy only where consensus semantics require it:
coinbase transactions are rejected from the mempool but remain valid block
issuance candidates for the later block-level uniqueness/state checks.

**Acceptance:** Added mempool-vs-block matrix tests for malformed non-coinbase
transactions so duplicate-nullifier public-shape failures and malformed proof
failures reject consistently from both paths.

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

**2026-07-09 Evidence:** Recursive proof verification now rejects empty proof
bodies and transaction-count prefixes above the bounded verifier cap before
constructing the matching keygen circuit, preventing malformed gossip/block
proof bytes from requesting unbounded recursive verifier work.

**Acceptance:** Node configuration determines aggregation mode; tests prove no
silent downgrade from full verification to trusted mode.

---

### PC-013 — P2 — Stub recursive manager surfaces can be mistaken for production support

**Phase:** 6

**Status:** Partially fixed. The P2P recursive manager now exposes
`RecursiveManagerMode::StubUnavailable`, `supports_production_proofs() == false`,
and generated proof JSON includes `mode: "stub_unavailable"` alongside
`status: "unavailable"`.

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
