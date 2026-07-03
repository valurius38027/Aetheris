#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Vendor PSE Halo2 into the Aetheris repository so that `cargo check --workspace`
  works without live GitHub fetches.

.DESCRIPTION
  Imports the full PSE Halo2 workspace into aetheris-zkp/vendor/halo2/,
  preserving existing Aetheris-local patches (halo2_backend, halo2_middleware).
  Optionally rewrites the root Cargo.toml to point to the vendored path and
  removes the now-unnecessary [patch] sections.

  NOTE: poseidon-circuit was previously a git dependency but is unused in this
  workspace (Poseidon is implemented in-tree). It has been removed from Cargo.toml.

.PARAMETER Halo2Src
  Path to a local PSE Halo2 workspace (directory containing Cargo.toml).

.PARAMETER Clone
  If set, clone the repository from GitHub (requires network access).

.PARAMETER Halo2Ref
  Git ref (branch / tag / commit) for Halo2.  Default: main.

.PARAMETER ApplyCargoPaths
  If set, rewrite Cargo.toml to use local path dependencies and
  remove the now-unnecessary [patch] sections.

.EXAMPLE
  .\scripts\vendor_pse_deps.ps1 -Halo2Src C:\src\halo2 -ApplyCargoPaths

.EXAMPLE
  .\scripts\vendor_pse_deps.ps1 -Clone -Halo2Ref main -ApplyCargoPaths
#>
param(
    [string]$Halo2Src,
    [switch]$Clone,
    [string]$Halo2Ref = "main",
    [switch]$ApplyCargoPaths
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

function Write-Step { param([string]$Msg) Write-Host "==> $Msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [!!] $Msg" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if (-not $Clone -and -not $Halo2Src) {
    Write-Warn "No local source provided and --Clone not set."
    Write-Warn "Provide -Halo2Src or use -Clone to fetch from GitHub."
    exit 1
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) "aetheris_vendor_$(Get-Random)"

try {
    # -----------------------------------------------------------------------
    # Clone or copy source into temp
    # -----------------------------------------------------------------------
    if ($Clone) {
        Write-Step "Cloning PSE Halo2 (ref: $Halo2Ref) ..."
        git clone --depth 1 --branch $Halo2Ref "https://github.com/privacy-scaling-explorations/halo2.git" (Join-Path $tmpRoot "halo2")
        git -C (Join-Path $tmpRoot "halo2") checkout $Halo2Ref
        $Halo2Src = Join-Path $tmpRoot "halo2"
    }
    else {
        Write-Step "Using local source: $Halo2Src"
    }

    # Validate source
    if (-not (Test-Path (Join-Path $Halo2Src "Cargo.toml"))) {
        throw "Required manifest Cargo.toml not found in $Halo2Src"
    }

    # -----------------------------------------------------------------------
    # Back up existing Aetheris-local patches (halo2_backend, halo2_middleware)
    # -----------------------------------------------------------------------
    $vendorRoot = Join-Path $repoRoot "aetheris-zkp" "vendor"
    $halo2Vendor = Join-Path $vendorRoot "halo2"
    $patchBackup = Join-Path $tmpRoot "aetheris-halo2-patches"

    if (Test-Path $halo2Vendor) {
        Write-Step "Backing up existing Aetheris-local Halo2 patches ..."
        New-Item -ItemType Directory -Path $patchBackup -Force | Out-Null
        foreach ($crate in @("halo2_backend", "halo2_middleware")) {
            $src = Join-Path $halo2Vendor $crate
            if (Test-Path $src) {
                Write-OK "  Saving $crate"
                Copy-Item -Recurse -Path $src -Destination (Join-Path $patchBackup $crate)
            }
        }
    }

    # -----------------------------------------------------------------------
    # Import the full Halo2 workspace
    # -----------------------------------------------------------------------
    Write-Step "Importing Halo2 workspace into $halo2Vendor ..."
    if (Test-Path $halo2Vendor) {
        Remove-Item -Recurse -Force -Path $halo2Vendor
    }
    New-Item -ItemType Directory -Path $halo2Vendor -Force | Out-Null
    Copy-Item -Recurse -Path (Join-Path $Halo2Src "*") -Destination $halo2Vendor -Exclude @(".git")

    # -----------------------------------------------------------------------
    # Restore Aetheris-local patches over the imported tree
    # -----------------------------------------------------------------------
    if (Test-Path $patchBackup) {
        Write-Step "Restoring Aetheris-local patches over imported Halo2 ..."
        foreach ($crate in @("halo2_backend", "halo2_middleware")) {
            $src = Join-Path $patchBackup $crate
            if (Test-Path $src) {
                $dst = Join-Path $halo2Vendor $crate
                if (Test-Path $dst) {
                    Remove-Item -Recurse -Force -Path $dst
                }
                Copy-Item -Recurse -Path $src -Destination $dst
                Write-OK "  Restored $crate"
            }
        }
    }

    # -----------------------------------------------------------------------
    # Verify vendored structure
    # -----------------------------------------------------------------------
    Write-Step "Verifying vendored structure ..."
    $required = @(
        (Join-Path $halo2Vendor "Cargo.toml"),
        (Join-Path $halo2Vendor "halo2_proofs" "Cargo.toml"),
        (Join-Path $halo2Vendor "halo2_backend" "Cargo.toml"),
        (Join-Path $halo2Vendor "halo2_middleware" "Cargo.toml")
    )
    foreach ($f in $required) {
        if (-not (Test-Path $f)) {
            throw "Vendored dependency incomplete: missing $f"
        }
    }
    Write-OK "All required manifests present."

    # -----------------------------------------------------------------------
    # Optionally rewrite Cargo.toml to local path dependencies
    # -----------------------------------------------------------------------
    if ($ApplyCargoPaths) {
        Write-Step "Rewriting Cargo.toml to use local path dependencies ..."
        $cargoToml = Join-Path $repoRoot "Cargo.toml"
        $content = Get-Content $cargoToml -Raw

        # Replace git dependency for halo2_proofs
        $content = $content -replace `
            'halo2_proofs\s*=\s*\{ git = "https://github.com/privacy-scaling-explorations/halo2.git", branch = "main" \}',
            'halo2_proofs = { path = "aetheris-zkp/vendor/halo2/halo2_proofs" }'

        # Remove [patch.crates-io] section (no longer needed with local path)
        $content = $content -replace '(?ms)^\[patch\.crates-io\].*?(?=\n\[|\z)', ''

        # Remove [patch.'https://github.com/privacy-scaling-explorations/halo2.git'] section
        $content = $content -replace "(?ms)^\[patch\.'https://github\.com/privacy-scaling-explorations/halo2\.git'].*?(?=\n\[|\z)", ''

        Set-Content -Path $cargoToml -Value $content -Encoding UTF8
        Write-OK "Cargo.toml updated."

        Write-Step "Generating Cargo.lock ..."
        Push-Location $repoRoot
        try {
            cargo generate-lockfile
            if ($LASTEXITCODE -ne 0) { throw "cargo generate-lockfile failed" }
            Write-OK "Cargo.lock generated."
        }
        finally { Pop-Location }
    }

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  Vendoring complete!" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    if (-not $ApplyCargoPaths) {
        Write-Host "  1. Update Cargo.toml to use local path:"
        Write-Host "     halo2_proofs = { path = ""aetheris-zkp/vendor/halo2/halo2_proofs"" }"
        Write-Host "  2. Remove [patch.crates-io] and [patch.'...halo2.git'] sections"
        Write-Host "  3. Run: cargo generate-lockfile"
    }
    Write-Host "  4. Run: cargo check --workspace" -ForegroundColor Cyan
    Write-Host ""
}
finally {
    if (Test-Path $tmpRoot) {
        Remove-Item -Recurse -Force -Path $tmpRoot -ErrorAction SilentlyContinue
    }
}
