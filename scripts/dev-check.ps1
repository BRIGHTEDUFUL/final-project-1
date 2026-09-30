# Runs the same quality gate used before every commit: lint, then tests.
$ErrorActionPreference = "Stop"

Write-Host "==> ruff check ." -ForegroundColor Cyan
ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> pytest" -ForegroundColor Cyan
pytest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> all checks passed" -ForegroundColor Green
