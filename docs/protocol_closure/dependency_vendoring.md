# Dependency Vendoring Runbook

This runbook is the Phase 0 dependency-reproducibility gate for Aetheris. The
protocol crates must not depend on live GitHub fetches during normal build and
test runs.

## Why this gate exists

The workspace currently names live git dependencies for PSE Halo2. That makes
`cargo check --workspace` dependent on network access and on floating branch
state. For protocol work, that is not acceptable: the source tree used by
reviewers must be the same source tree used by builders.

## Required local dependencies

Vendor these sources into the repository:

- `aetheris-zkp/vendor/halo2/` — the full PSE Halo2 workspace, not only selected
  subcrates.

The existing Aetheris-local `halo2_backend` and `halo2_middleware` directories
must be preserved when importing a full Halo2 tree because they contain the local
patch surface used by this repository.

> **Note:** `poseidon-circuit` was previously listed as a git dependency but is
> **unused** in this workspace (Poseidon is implemented in-tree as
> `aetheris-zkp/src/poseidon_fq.rs` + `poseidon_fq_chip.rs`). The dead dependency
> has been removed from `Cargo.toml` and does not need to be vendored.

## Import command

If the dependency sources are already available locally:

```powershell
scripts/vendor_pse_deps.ps1 -Halo2Src /path/to/privacy-scaling-explorations/halo2 -ApplyCargoPaths
```

If GitHub is reachable from the machine doing the import:

```powershell
scripts/vendor_pse_deps.ps1 -Clone -Halo2Ref <reviewed-ref> -ApplyCargoPaths
```

Prefer fixed reviewed refs over floating branches. After import, commit the
vendored source, the `Cargo.toml` path rewrite, and the generated `Cargo.lock`.

## Acceptance checks

Run these before continuing protocol-closure implementation:

```bash
cargo generate-lockfile
cargo metadata --no-deps --format-version 1
cargo check --workspace
```

Then run the safe crate-specific tests from `AGENTS.md`; do not run the full
recursive test suite without a filter and limited parallelism.

## Failure policy

If the full vendored Halo2 workspace is missing, do not replace it with an
unreviewed crates.io release merely to make Cargo compile. This repository relies
on the PSE fork and local Halo2 patch surface; changing that dependency is an
architecture/security decision, not a build convenience.
