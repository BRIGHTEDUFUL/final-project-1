# Rogue AP Hunter

**Live Wi-Fi Rogue Access Point Detection and Alert System** — a free,
open-source, offline-first Windows desktop application that continuously
monitors nearby Wi-Fi networks and explains why a network looks like a rogue
access point or an Evil Twin.

> **Defensive tool.** Rogue AP Hunter never captures passwords, never
> intercepts or decrypts traffic, never attacks or disrupts wireless networks
> and never connects to suspicious networks automatically. It reports
> *observable metadata patterns*, not proof of malicious intent.

---

## Status

Phase 0 — project foundation (this build).

| Area | State |
|------|-------|
| Repository structure, packaging metadata, logging, configuration | ✅ done |
| Windows scanner adapter (`netsh wlan`) | ⏳ Phase 1 |
| Parsing and domain models | ⏳ Phase 2 |
| SQLite storage | ⏳ Phase 3 |
| Trusted baseline, detection, scoring | ⏳ Phases 4–6 |
| Dashboard and investigation UI | ⏳ Phases 7–8 |
| History, settings, tests, packaging | ⏳ Phases 9–12 |

## What it will do

- Watch the wireless environment reported by the local Windows adapter.
- Keep **trusted network profiles** (approved SSIDs, BSSIDs, expected security).
- Flag duplicate SSIDs on unfamiliar BSSIDs, security downgrades, new access
  points and suspicious persistence — with an **explainable risk score**.
- Raise visual and desktop alerts, store everything locally in SQLite, and
  export history to CSV.

## Requirements

- Windows 10/11
- Python 3.11 or newer (3.14 tested)
- A wireless adapter with working WLAN support
- No internet connection required after installation

## Installation

```powershell
git clone <repository-url> rogue-ap-hunter
cd rogue-ap-hunter
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Running

```powershell
rogue-ap-hunter                # start the graphical interface
rogue-ap-hunter --headless     # initialise config + logging, then exit
rogue-ap-hunter --version
rogue-ap-hunter --write-default-config
python -m app                  # equivalent entry point
```

Exit codes: `0` success · `1` runtime failure · `2` invalid arguments ·
`3` graphical interface unavailable.

## Development

```powershell
pytest              # run the automated test suite
ruff check .        # lint
ruff format .       # format
.\scripts\dev-check.ps1   # lint + tests in one step
```

Tests never require a live Wi-Fi environment.

## Where data lives

All data is local. Set `ROGUE_AP_HUNTER_HOME` to relocate it (portable mode).
By default the application directory is
`%LOCALAPPDATA%\Rogue AP Hunter\` containing:

```
config.json                 settings and risk weights
logs/rogue-ap-hunter.log    rotating application log
data/rogue_ap_hunter.sqlite3  observations, alerts, profiles (Phase 3)
```

## Repository layout

```
rogue-ap-hunter/
├── app/
│   ├── core/        configuration, logging, paths
│   ├── scanner/     Windows WLAN scan adapters
│   ├── parser/      raw output parsing and normalisation
│   ├── models/      domain objects
│   ├── detection/   detection rules
│   ├── scoring/     explainable risk scoring
│   ├── storage/     SQLite persistence
│   ├── alerts/      alert lifecycle
│   ├── services/    monitoring and background services
│   └── ui/          PySide6 interface
├── tests/           unit, integration and fixtures
├── docs/            setup, architecture, methodology
├── scripts/         developer helpers
├── assets/          icons and images
└── pyproject.toml
```

## Technology stack

Python 3 · PySide6 · `netsh wlan` · SQLite · Matplotlib · pytest · Ruff ·
Git · PyInstaller. Every component is free or open source — see
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md). There is no paid API,
no cloud dependency and no telemetry.

## Responsible use

Test only on networks and equipment you own or are explicitly authorised to
assess. Findings are heuristic indicators based on scan metadata; they do not
establish malicious intent. See [`docs/setup.md`](docs/setup.md) for the
developer setup guide.

## License

MIT — see [`LICENSE`](LICENSE).
