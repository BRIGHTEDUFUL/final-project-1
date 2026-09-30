<#
.SYNOPSIS
    Reproducible Windows build of Rogue AP Hunter with PyInstaller.

.DESCRIPTION
    Creates dist\RogueAPHunter\RogueAPHunter.exe (onedir by default) from the
    repository using the local virtual environment. The build is offline and
    uses only free tools: Python, PyInstaller and the project dependencies.

.PARAMETER Console
    Attach a console window to the executable (CLI/debug builds).

.PARAMETER OneFile
    Pack everything into a single executable instead of a directory bundle.

.PARAMETER Clean
    Remove build/ and dist/ before building (recommended for releases).

.EXAMPLE
    .\scripts\build.ps1
    .\scripts\build.ps1 -Clean -Console
#>
[CmdletBinding()]
param(
    [switch]$Console,
    [switch]$OneFile,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Virtual environment not found at $python. Run: python -m venv .venv && .\.venv\Scripts\pip install -e `".[dev]`""
    exit 1
}

$pyInstaller = Join-Path $repoRoot ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $pyInstaller)) {
    Write-Host "Installing PyInstaller into the virtual environment..."
    & $python -m pip install --disable-pip-version-check pyinstaller
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

# Environment switches consumed by rogue-ap-hunter.spec.
$env:ROGUE_AP_HUNTER_CONSOLE = if ($Console) { "1" } else { "0" }
$env:ROGUE_AP_HUNTER_ONEFILE = if ($OneFile) { "1" } else { "0" }

if ($Clean) {
    Write-Host "Cleaning previous build output..."
    foreach ($dir in @("build", "dist")) {
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    }
}

Write-Host "Running static checks before packaging..."
& (Join-Path $repoRoot ".venv\Scripts\ruff.exe") check .
if ($LASTEXITCODE -ne 0) { Write-Error "ruff reported problems; aborting build."; exit 1 }

Write-Host "Running test suite before packaging..."
& $python -m pytest
if ($LASTEXITCODE -ne 0) { Write-Error "tests failed; aborting build."; exit 1 }

Write-Host "Building with PyInstaller (console=$Console, onefile=$OneFile)..."
& $pyInstaller --noconfirm --clean --distpath dist --workpath build (Join-Path $repoRoot "rogue-ap-hunter.spec")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$exeName = if ($OneFile) { "dist\RogueAPHunter.exe" } else { "dist\RogueAPHunter\RogueAPHunter.exe" }
if (-not (Test-Path $exeName)) {
    Write-Error "Build finished but $exeName is missing."
    exit 1
}

Write-Host ""
Write-Host "Build complete: $exeName"
Write-Host "Smoke test:     & '$exeName' --version"
Write-Host "Launch:         & '$exeName'"
