# Aetheris Protocol Closure Tracker

This directory is the independent planning and tracking source for moving Aetheris
from the currently audited prototype state to an initially closed protocol. It is
intentionally based on observed source behavior and reproducible checks, not on
legacy roadmap claims or phase labels elsewhere in the repository.

## Scope

"Protocol initially closed" means the minimal end-to-end system has a coherent
security story across these boundaries:

1. **Build boundary** — the workspace resolves, checks, and has a safe test
   matrix that does not require running memory-heavy recursive tests by default.
2. **Transaction boundary** — a transaction proves ownership, membership,
   value conservation, output commitment correctness, and nullifier correctness
   in one verification path accepted by nodes.
3. **Wallet boundary** — wallet send/scan uses one address, viewing-key,
   encryption, and note format; prototype local-file paths are dev-only.
4. **Node boundary** — mempool and block validation enforce the same transaction
   validity rules, genesis identity rules, VDF rules, issuance rules, and state
   transition rules.
5. **Recursive boundary** — aggregation has a documented trust model and a
   verifiable fallback; stub manager surfaces cannot be mistaken for production
   recursive proof support.
6. **FFI boundary** — exported functions have explicit ownership, nullability,
   length, panic, and error contracts.
7. **Audit boundary** — every security-sensitive phase ends with targeted tests,
   negative tests, and an independent review checklist.

## Files

- [`protocol_closure_plan.md`](protocol_closure_plan.md) — phased execution plan
  from current state to initial protocol closure.
- [`progress.md`](progress.md) — status board and acceptance-gate checklist.
- [`issues.md`](issues.md) — normalized issue backlog derived from the audit.

## Working Model

This tracker avoids heavyweight ritual. Each phase uses a compact loop:

1. Define the phase boundary and invariants.
2. Make the smallest set of source changes that closes those invariants.
3. Run the phase's required checks and negative tests.
4. Record evidence in `progress.md` and update issue states.
5. Run a focused security review for only the changed boundary.

A phase is complete only when its acceptance gate is green and the next phase can
rely on its invariants without re-litigating them.
