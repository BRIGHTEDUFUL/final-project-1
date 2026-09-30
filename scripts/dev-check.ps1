# Runs the same quality gate used before every commit: lint, then tests.
# Works with or without the virtual environment pre-activated.
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$venvScripts = Join-Path $repoRoot ".venv\Scripts"
if (Test-Path $venvScripts) {
    $env:PATH = "$venvScripts;$env:PATH"
}

Write-Host "==> ruff check ." -ForegroundColor Cyan
if (Test-Path (Join-Path $venvScripts "ruff.exe")) {
    & (Join-Path $venvScripts "ruff.exe") check .
} else {
    python -m ruff check .
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> pytest" -ForegroundColor Cyan
if (Test-Path (Join-Path $venvScripts "pytest.exe")) {
    & (Join-Path $venvScripts "pytest.exe")
} else {
    python -m pytest
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> all checks passed" -ForegroundColor Green
