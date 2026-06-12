# AI Agent Work Guidelines for Aetheris

## Phase Execution Workflow

Every phase follows this strict cycle:

1. **Multi-Agent Investigation** — Launch 2+ parallel subagents to analyze the codebase
   - Each agent independently identifies issues from different perspectives
   - Return structured findings with file/line references
2. **Implement Fixes** — Human/AI lead reads findings, implements all fixes
3. **Test** — `cargo check --workspace` must be clean (zero errors, zero warnings).
   Then run applicable tests with appropriate filter and limited parallelism.
   NEVER run all tests at once (`aetheris-recursive` K=17/18 circuits = OOM).
   See Commands section for safe patterns.
4. **Multi-Agent Review** — Launch 2+ parallel subagents to review ALL changes
   - Verify correctness, no regressions, edge cases, test coverage
   - Return: ✅ APPROVED / ⚠️ WARNINGS / ❌ ISSUES
   - Fixes from previous iterations must be re-verified
5. **Iterate** — If any reviewer returns ❌ ISSUES or unresolved ⚠️ WARNINGS:
   - Go back to step 2 → 3 → 4 (never skip step 4)
6. **Commit** — Only after ALL reviewers pass with zero blocking issues

## Principles

- **Do NOT write code during investigation/review** — only read, analyze, report
- **Be maximally critical** — easier to tone down harsh feedback than to catch misses
- **Phase isolation** — never modify files outside the current phase's scope
- **Verify everything** — compile + test after every fix batch, no exceptions

---

## Repo Structure & Conventions

### Workspace (7 crates)
| Crate | Purpose |
|-------|---------|
| `aetheris-core` | Core types (Block, Transaction, Amount, Hash), constants, genesis |
| `aetheris-crypto` | Class group VDF, Wesolowski proof, trace macros |
| `aetheris-zkp` | Halo2 IPA commitment + shielded tx circuit (PSE fork) |
| `aetheris-node` | P2P libp2p node, sled-backed state, consensus |
| `aetheris-wallet` | CLI wallet (mnemonic, scan, send) |
| `aetheris-ffi` | C-ABI bridge (30+ extern "C" functions) |
| `aetheris-recursive` | Recursive proof aggregation (known-buggy — see below) |

### Halo2 Vendor Patches
The PSE halo2 fork is patched at `aetheris-zkp/vendor/halo2/` and mapped via `[patch]` in workspace `Cargo.toml`. Key change: visibility of query types relaxed from `pub(crate)` → `pub`. If patching or upgrading, coordinate both the git dep AND the vendor patches.

### Known Limitations (read before working)
- **IPA + PLONK multiopen integration** — h_eval constraint was fixed in Phase 1.11.5 (`extended_k=13`). `ISSUE_IPA_PLONK_INTEGRATION.md` is **outdated** and no longer reflects the current state. The constraint check at `vanishing/verifier.rs:142-144` is active.
- **Permutation label mismatch** — `constrain_equal` calls in branch-dependent code produce different permutation labels between keygen and proving, causing IPA verification failure. **Never use `constrain_equal` in a branch-dependent way** (e.g., based on `position_bits`). Use Gate-based input selection instead. See `protocol_design_ruling.md §2.2` for the approved pattern.
- **`aetheris-recursive`** — B-2 migration **COMPLETE**. The native Vesta IPA accumulation circuit is implemented (see `aetheris-recursive/B-2_plan.md`). Old files `ipa_fold.rs`, `non_native_mul.rs`, `ipa_verifier_circuit.rs` deleted. `non_native_fq.rs` retained for transcript gadget (Phase 6).
- **Coq proofs** in `formal_proof/` are stubs/placeholders, not verified.
- **Wallet encryption/send/scan** has placeholder-simulated paths.

### Key Architecture References
- `protocol_design_ruling.md` — final design decisions (Pasta curves, IPA accumulation, ZK abstraction)
- `aetheris-recursive/B-2_plan.md` — ✅ Completed implementation plan for native IPA accumulation on Vesta
- `FINAL_ARCHITECTURAL_PLAN.md` — **Active master plan** for Phase 1.4 B-3 CircuitAccumulate, Poseidon migration, block cleanup, P2P layer, and all remaining architectural alignment.
- `aetheris-recursive/B-3_plan.md` — ⚠️ SUPERSEDED by FINAL_ARCHITECTURAL_PLAN.md
- `aetheris-recursive/phase_1_14_plan.md` — ⚠️ SUPERSEDED by FINAL_ARCHITECTURAL_PLAN.md §C–§D
- `math_spec.md` — VDF, class group, record model math
- `genesis.json` — genesis config (network, VDF difficulty)
- `gen_crs.ps1` — CRS generation for Halo2 params

## Commands

```bash
# Build & check everything (must always pass before commit)
cargo check --workspace

# Test safety: NEVER run all tests at once (aetheris-recursive has K=17/18
# circuits consuming 2-4GB+ each → OOM). ALWAYS filter by test name and
# limit parallelism.
cargo test -p aetheris-zkp -- --test-threads=4
cargo test -p aetheris-recursive --lib -- <prefix> --test-threads=2
cargo test -p aetheris-core
cargo test -p aetheris-crypto

# FFI tests — MUST run with --test-threads=1 (sled Windows file lock)
cargo test -p aetheris-ffi --lib -- --test-threads=1
```

No formatter (`rustfmt.toml`) or linter (`clippy.toml`) config exists — workspace uses defaults.
No CI workflows configured.
Debug tracing: set `AETHERIS_TRACE=1` env var (uses `trace!`/`trace_elapsed!` macros in `aetheris-crypto`).
