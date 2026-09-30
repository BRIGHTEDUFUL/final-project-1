# Windows Packaging Guide

Rogue AP Hunter ships as a native Windows executable built with
[PyInstaller](https://pyinstaller.org) — a free, open-source tool. The build
runs entirely offline: no paid services, no code signing infrastructure, no
network access beyond installing dependencies into the virtual environment.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Windows 10/11 (x64) | Build and target on the same OS generation |
| Python 3.11+ | The repository uses `.venv` (Python 3.14 verified) |
| Project dependencies | `pip install -e ".[dev]"` |
| PyInstaller | Installed automatically by `scripts/build.ps1`, or `pip install pyinstaller` |

Everything else (PySide6, matplotlib, SQLite) is bundled into the output.

## Building

From the repository root:

```powershell
# Default release build: windowed, one-folder bundle
.\scripts\build.ps1 -Clean

# Console build (CLI output visible; useful for debugging)
.\scripts\build.ps1 -Clean -Console

# Single-file executable (convenient to copy, slower to start)
.\scripts\build.ps1 -Clean -OneFile
```

The script always runs, in order:

1. `ruff check .` — packaging is aborted on lint errors.
2. `pytest` — packaging is aborted on test failures.
3. `pyinstaller --noconfirm --clean rogue-ap-hunter.spec`.

Output:

```
dist\RogueAPHunter\RogueAPHunter.exe   # default (onedir) build
dist\RogueAPHunter.exe                 # -OneFile build
```

Build intermediates live in `build/` and are safe to delete; both directories
are ignored by git.

### What the spec bundles

`rogue-ap-hunter.spec` collects:

* the application code (`app/main.py` and its imports),
* `assets/`, `docs/`, `LICENSE`, and `THIRD_PARTY_LICENSES.md`,
* the Qt and matplotlib backends actually used (`matplotlib.backends.backend_qtagg`),
* nothing else — unused GUI backends (Tk, Qt5) are excluded to keep the
  bundle small.

Two environment switches drive the spec (set by `scripts/build.ps1`):

| Variable | Effect |
| --- | --- |
| `ROGUE_AP_HUNTER_CONSOLE=1` | attach a console window to the executable |
| `ROGUE_AP_HUNTER_ONEFILE=1` | pack everything into one executable |

## Verifying a build

```powershell
$exe = ".\dist\RogueAPHunter\RogueAPHunter.exe"

& $exe --version          # prints "Rogue AP Hunter <version>", exit code 0
& $exe --headless         # initialises config + logging, exit code 0
& $exe                    # opens the window
```

`--headless` is the fastest smoke test: it creates the per-user data
directories, writes a log file, and exits without needing a display.

Exit codes (identical for the packaged and source builds):

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | unexpected runtime failure (e.g. local storage unavailable) |
| 2 | invalid command line arguments |
| 3 | graphical interface could not be started (PySide6 missing/broken) |

## Launching on an end-user machine

1. Copy the whole `dist\RogueAPHunter\` folder anywhere (for example
   `C:\Program Files\Rogue AP Hunter\` or a USB stick).
2. Run `RogueAPHunter.exe`. No Python installation is required on the target.
3. Configuration, logs and the SQLite database are written to
   `%LOCALAPPDATA%\Rogue AP Hunter\` (override the root with the
   `ROGUE_AP_HUNTER_HOME` environment variable).

The application never requires administrator rights: it only reads the
wireless environment through `netsh wlan` and writes to its own data folder.

### First-run notes

* **SmartScreen / antivirus warnings.** Unsigned open-source executables are
  frequently flagged heuristically. Choose "More info" → "Run anyway" for builds
  you compiled yourself, and verify the hash if you downloaded one:
  `Get-FileHash .\RogueAPHunter.exe -Algorithm SHA256`.
* **No window appears.** Check
  `%LOCALAPPDATA%\Rogue AP Hunter\logs\rogue-ap-hunter.log`, or run the
  console build (`scripts\build.ps1 -Console`) to see the error directly.
* **Charts missing.** The investigation screen degrades gracefully when
  matplotlib's Qt backend cannot load; the log records the reason.

## Reproducibility

* The build is a single deterministic entry point (`scripts/build.ps1`) that
  refuses to package failing lint or tests.
* All inputs are local: the spec, the repository files, and the versions
  pinned in `pyproject.toml` (`PySide6>=6.6`, `matplotlib>=3.8`).
* Rebuild the same commit with the same dependency versions to obtain an
  equivalent bundle; record `python -m pip freeze` alongside release archives
  if bit-for-bit auditing matters.
* The spec intentionally skips code signing, icons and version resources so
  that no certificates or proprietary tools are required. Adding them later is
  an optional, documented extension.

## CI

`.github/workflows/ci.yml` runs lint and the test suite on pushes. Packaging
is kept as a local Windows step because PyInstaller output is platform-bound;
run `scripts\build.ps1` on a Windows runner if you add a release job.

## Troubleshooting the build

| Symptom | Cause / fix |
| --- | --- |
| "Virtual environment not found" | create it first: `python -m venv .venv` then `.\.venv\Scripts\pip install -e ".[dev]"` |
| `ruff reported problems; aborting build` | fix lint errors; the build intentionally stops |
| `tests failed; aborting build` | fix failing tests; the build intentionally stops |
| Missing matplotlib chart in the bundle | confirm `matplotlib.backends.backend_qtagg` is still listed in `hiddenimports` |
| Antivirus quarantines `RogueAPHunter.exe` | rebuild locally and add an exclusion for `dist\`; the bootloader is unsigned |
| Huge bundle size | use `-OneFile` for distribution, or run with `-Clean` to drop stale intermediates |
