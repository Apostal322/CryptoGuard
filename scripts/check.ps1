# Local equivalent of .github/workflows/ci.yml (Windows PowerShell). Exits non-zero on the
# first failing step. No network access except what npm ci / uv sync need for missing
# packages. Usage: .\scripts\check.ps1 [-SkipE2E]
param([switch]$SkipE2E)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$results = @()

function Step([string]$name, [scriptblock]$body) {
    $start = Get-Date
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    $script:results += "{0,-28} ok  {1,6:n0} s" -f $name, ((Get-Date) - $start).TotalSeconds
}

Write-Host ("Environment: {0}; {1}; node {2}" -f (Get-CimInstance Win32_OperatingSystem).Caption, (uv run python --version), (node --version))

Step "uv sync --locked" { uv sync --locked }
Step "ruff check" { uv run ruff check . }
Step "ruff format --check" { uv run ruff format --check . }
Step "mypy" { uv run mypy src }
Step "pytest" { uv run pytest -q }
Step "uv build" { uv build --out-dir dist }
Step "inspect dist" { uv run python scripts/inspect_dist.py dist }
Push-Location apps/web
try {
    Step "npm ci" { npm ci }
    Step "typecheck" { npm run typecheck }
    Step "vitest" { npm test }
    Step "build" { npm run build }
    if (-not $SkipE2E) { Step "playwright e2e" { npx playwright test } }
} finally { Pop-Location }

Write-Host "`nAll steps passed:" -ForegroundColor Green
$results | ForEach-Object { Write-Host "  $_" }
