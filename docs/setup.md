# Developer Setup Guide

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows 10/11 | Target platform for scanning and packaging |
| Python 3.11+ | 3.14 is the version used during development |
| Git | Version control |
| Wireless adapter | Required for scanning phases (Phase 1+); **not** required to run the tests |
| Npcap driver *(optional)* | Free installer from npcap.com; enables the passive beacon-frame observer. Not bundled, not required — without it the app reports `unavailable — Npcap/WinPcap driver not found` in Settings and stays fully netsh-only. Tests skip the live capture check. |

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
| Run tests | `pytest` (or `.\.venv\Scripts\pytest.exe` without activating the venv) |
| Run only the fast unit tests | `pytest tests/unit` |
| Lint | `ruff check .` (or `.\.venv\Scripts\ruff.exe check .`) |
| Auto-fix import order | `ruff check --fix .` |
| Format | `ruff format .` |
| Lint + tests in one step | `.\scripts\dev-check.ps1` |
| Write the default config file | `rogue-ap-hunter --write-default-config` |
| Package a Windows build | `.\scripts\build.ps1` (runs ruff + tests, then PyInstaller) |
| Offline performance benchmark | `.\.venv\Scripts\python.exe scripts\benchmark.py --iterations 20 --scans 50` (see [`performance.md`](performance.md)) |

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
- Modular layers: scanner → parser → storage → detection → scoring → alerts →
  monitoring service → Qt UI, wired in `AppContext`. UI code never performs
  detection or database access directly; domain models import nothing outside
  the standard library.
- No silent exception swallowing: log with context or propagate.
- No hard-coded environment-specific paths — resolve through
  `app.core.paths`.
- Tests for all non-trivial logic; tests must not require a live Wi-Fi network.
- Only free/open-source dependencies; update `THIRD_PARTY_LICENSES.md` when
  adding one.

## 6. Git workflow

```powershell
git checkout -b feature/<short-name>
git add <explicit paths>          # stage what you changed, not the whole tree
git commit -m "<area>: what changed and why"
git push -u origin feature/<short-name>
```

Commit messages name the area first, e.g.
`Detection: duplicate-SSID rule with evidence`. (Some early commits used the
`Phase N:` form; both appear in the history.)

## 7. Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| `rogue-ap-hunter` not found | Activate the virtual environment, or use `python -m app` |
| Exit code `3` on start | PySide6 missing — `pip install -e ".[dev]"`, or use `--headless` |
| Tests appear to touch real data | Startup tests redirect `ROGUE_AP_HUNTER_HOME` into a temporary directory themselves; other tests use `tmp_path` — nothing is written to your real application data |
| `netsh` reports no wireless interface | Enable the wireless adapter or start the `WlanSvc` service; see [`troubleshooting.md`](troubleshooting.md) §1 |
| Stale settings after a version change | Delete `config.json` or run `--write-default-config` to a new path |
