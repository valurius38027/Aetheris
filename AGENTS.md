# AI Agent Work Guidelines for Aetheris

## Phase Execution Workflow

Every phase follows this strict cycle:

1. **Multi-Agent Investigation** — Launch 2+ parallel subagents to analyze the codebase
   - Each agent independently identifies issues from different perspectives
   - Return structured findings with file/line references
2. **Implement Fixes** — Human/AI lead reads findings, implements all fixes
3. **Test** — `cargo check --workspace` must be clean (zero errors, zero warnings).
   Then run `cargo test --workspace --lib` (omit `--lib` if integration tests exist).
   Run all applicable tests, not just the ones related to the change.
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
- **IPA + PLONK multiopen integration** is broken. See `ISSUE_IPA_PLONK_INTEGRATION.md` for root cause and attempted fixes. Any vanishing argument or permutation work touches this.
- **`aetheris-recursive`** (`NonNativeChip`, `AccumulatorChip`, `KzgChip`) has known correctness bugs — not a real recursive SNARK. Cross-crate fixes touching this crate's types may need additional care.
- **Coq proofs** in `formal_proof/` are stubs/placeholders, not verified.
- **Wallet encryption/send/scan** has placeholder-simulated paths.

### Key Architecture References
- `protocol_design_ruling.md` — final design decisions (Pasta curves, IPA accumulation, ZK abstraction)
- `math_spec.md` — VDF, class group, record model math
- `genesis.json` — genesis config (network, VDF difficulty, allocations)
- `gen_crs.ps1` — CRS generation for Halo2 params

## Commands

```bash
# Build & check everything (must always pass before commit)
cargo check --workspace

# Run all library tests across workspace
cargo test --workspace --lib

# Run single crate tests
cargo test -p aetheris-zkp

# FFI tests — MUST run with --test-threads=1 (sled Windows file lock)
cargo test -p aetheris-ffi --lib -- --test-threads=1
```

No formatter (`rustfmt.toml`) or linter (`clippy.toml`) config exists — workspace uses defaults.
No CI workflows configured.
Debug tracing: set `AETHERIS_TRACE=1` env var (uses `trace!`/`trace_elapsed!` macros in `aetheris-crypto`).
