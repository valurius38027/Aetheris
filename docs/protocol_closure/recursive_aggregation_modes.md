# Recursive Aggregation Modes

This note records the current trust modes for recursive block aggregation so
node, FFI, and future RPC configuration changes cannot silently reinterpret an
empty or malformed aggregate proof.

## Mode table

| Mode | Current status | Accepted proof shape | Trust assumption | Intended use |
| --- | --- | --- | --- | --- |
| `genesis-empty` | Implemented | Height-0 genesis only: empty `recursive_proof` and locked genesis identity | The locked fair-launch genesis is a hard-coded trust anchor. | Mainnet genesis bootstrapping. |
| `verified-recursive` | Implemented for non-empty proofs | Non-empty recursive proof with a 104-byte prefix (`Q.x`, `Q.y`, transcript, depth, `num_txs`) and bounded `num_txs`; verifier rejects malformed prefixes before keygen. | Node verifies the recursive proof against the block state root before state mutation. | Production block validation target. |
| `legacy-empty-non-genesis` | Compatibility fallback, not production-final | Non-genesis blocks with empty `recursive_proof` are accepted only when the ledger is configured with `RecursiveProofPolicy::LegacyAllowEmptyNonGenesis`. | Trust falls back to explicit transaction/state/VDF checks; it is not an O(1) aggregate proof. | Transitional tests and legacy local flows only. |
| `trusted-signed-aggregate` | Not implemented as consensus policy | Signed aggregate metadata from a configured aggregator key. | Trust shifts to the configured aggregator key and must be opt-in. | Future fast path after explicit configuration and downgrade tests. |

## Current validation boundaries

- Genesis is strict: the node validates the locked fair-launch identity, empty
  transaction list, empty state root, VDF placeholders, and empty recursive proof
  before mutation.
- Non-empty recursive proofs are verified before transaction application and
  before block persistence.
- Recursive proof prefixes are resource-bounded before verifier keygen: empty
  proof bodies and oversized `num_txs` values are rejected immediately.
- Empty non-genesis recursive proofs are controlled by an explicit ledger
  `RecursiveProofPolicy`; strict mode rejects them before transaction mutation or
  block persistence, while the current default remains legacy compatibility until
  production configuration is finalized.

## Closure requirements

Phase 6 is not complete until the node has an explicit aggregation policy knob
with these properties:

1. Production/default mode must be switched to reject empty non-genesis
   `recursive_proof` values once tests and mining fixtures consistently produce
   recursive proofs.
2. Any trusted signed-aggregate mode is opt-in and bound to an explicitly
   configured verifier key.
3. Tests prove that configuration cannot silently downgrade from full recursive
   verification to trusted or legacy compatibility behavior.
4. Replay tests document whether replay verifies every transaction directly,
   recursive aggregates, or both.
