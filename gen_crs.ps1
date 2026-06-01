# Generates the canonical KZG CRS for Aetheris using true random entropy
# from random.org. The seed is used once and discarded — never stored in code.
#
# Usage: .\gen_crs.ps1
#
# Requires: Rust toolchain (cargo), internet access to random.org
#
# Output: aetheris-zkp/crs.bin

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "[1/3] Fetching 32 true random bytes from random.org ..." -ForegroundColor Cyan
try {
    $resp = Invoke-WebRequest -Uri "https://www.random.org/cgi-bin/randbyte?nbytes=32&format=h" -UseBasicParsing -TimeoutSec 30
    $hexSeed = ($resp.Content -replace '[^0-9a-fA-F]', '').Trim()
    if ($hexSeed.Length -ne 64) {
        Write-Host "  random.org returned $($hexSeed.Length) hex chars (expected 64), retrying with raw format..." -ForegroundColor Yellow
        $resp = Invoke-WebRequest -Uri "https://www.random.org/cgi-bin/randbyte?nbytes=32&format=f" -UseBasicParsing -TimeoutSec 30
        $bytes = [byte[]]($resp.Content -split '[\s,]+' | Where-Object { $_ -ne '' } | Select-Object -First 32)
        if ($bytes.Count -eq 32) {
            $hexSeed = -join ($bytes | ForEach-Object { $_.ToString("x2") })
        } else {
            throw "Failed to parse random.org response"
        }
    }
    Write-Host "  -> Got seed: $hexSeed" -ForegroundColor Gray
} catch {
    Write-Host "ERROR: Failed to fetch from random.org: $_" -ForegroundColor Red
    Write-Host "FALLBACK: Using OsRng as seed source (less auditable but still secure)." -ForegroundColor Yellow
    # Fallback to OsRng
    $seedBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($seedBytes)
    $hexSeed = -join ($seedBytes | ForEach-Object { $_.ToString("x2") })
    Write-Host "  -> Fallback seed: $hexSeed" -ForegroundColor Gray
}

Write-Host "[2/3] Building gen_crs tool ..." -ForegroundColor Cyan
cargo build -p aetheris-zkp --bin gen_crs --release
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

$GenCrsBin = Join-Path $ProjectRoot "target\release\gen_crs.exe"
$OutputPath = Join-Path $ProjectRoot "aetheris-zkp\crs.bin"

Write-Host "[3/3] Generating CRS with k=11 (this takes ~1 minute) ..." -ForegroundColor Cyan
& $GenCrsBin $hexSeed $OutputPath
if ($LASTEXITCODE -ne 0) { throw "CRS generation failed" }

Write-Host ""
Write-Host "SUCCESS: CRS written to aetheris-zkp/crs.bin" -ForegroundColor Green
Write-Host "The random seed has been discarded. Commit crs.bin to the repository."
Write-Host ""
Write-Host "To remove the deterministic-seed fallback, ensure crs.bin exists"
Write-Host "before building; ensure_params() will load from it automatically."
