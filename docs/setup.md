# Developer Setup Guide

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows 10/11 | Target platform for scanning and packaging |
| Python 3.11+ | 3.14 is the version used during development |
| Git | Version control |
| Wireless adapter | Required for scanning phases (Phase 1+); **not** required to run the tests |

## 2. Install

```powershell
git clone <repository-url> rogue-ap-hunter
cd rogue-ap-hunter
python -m venv .venv
.venv\Scripts\Activate.ps1        # PowerShell
# .venv\Scripts\activate.bat      # cmd.exe
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Verify the installation:

```powershell
rogue-ap-hunter --version
pytest
ruff check .
```

## 3. Everyday commands

| Task | Command |
|------|---------|
| Start the GUI | `rogue-ap-hunter` or `python -m app` |
| Headless initialisation check | `rogue-ap-hunter --headless` |
| Run tests | `pytest` |
| Run tests with coverage summary | `pytest -q` |
| Lint | `ruff check .` |
| Auto-fix import order | `ruff check --fix .` |
| Format | `ruff format .` |
| Lint + tests in one step | `.\scripts\dev-check.ps1` |
| Write the default config file | `rogue-ap-hunter --write-default-config` |

## 4. Configuration and data locations

| Item | Default location | Override |
|------|------------------|----------|
| Home directory | `%LOCALAPPDATA%\Rogue AP Hunter` | `ROGUE_AP_HUNTER_HOME` |
| Configuration | `<home>\config.json` | `--config PATH` |
| Log file | `<home>\logs\rogue-ap-hunter.log` | — |
| Database | `<home>\data\rogue_ap_hunter.sqlite3` | — |

Nothing is written outside these locations, and nothing is sent over the
network.

## 5. Project conventions

- Type hints on all public functions; docstrings for non-obvious behaviour.
- Modular layers: scanner → parser → models → detection → scoring → storage →
  alerts → UI. UI code never performs detection or database access directly.
- No silent exception swallowing: log with context or propagate.
- No hard-coded environment-specific paths — resolve through
  `app.core.paths`.
- Tests for all non-trivial logic; tests must not require a live Wi-Fi network.
- Only free/open-source dependencies; update `THIRD_PARTY_LICENSES.md` when
  adding one.

## 6. Git workflow

```powershell
git checkout -b feature/<short-name>
git add -A
git commit -m "Phase N: summary"
git push -u origin feature/<short-name>
```

Commit messages reference the development phase, e.g.
`Phase 5: duplicate-SSID detection rule with evidence`.

## 7. Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| `rogue-ap-hunter` not found | Activate the virtual environment, or use `python -m app` |
| Exit code `3` on start | PySide6 missing — `pip install -e ".[dev]"`, or use `--headless` |
| Tests write outside the temp dir | Tests set `ROGUE_AP_HUNTER_HOME`; do not unset it manually |
| `netsh` reports no interface (Phase 1+) | Enable the wireless adapter, or run `netsh wlan show drivers` to diagnose |
| Stale settings after a version change | Delete `config.json` or run `--write-default-config` to a new path |
