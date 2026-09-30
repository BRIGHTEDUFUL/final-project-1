# Rogue AP Hunter

**Live Wi-Fi rogue access point detection and alert system for Windows** — a
free, open-source, offline-first desktop application that watches the wireless
environment reported by your own adapter, compares it against a baseline *you*
approve, and explains every risk score it produces.

> **Defensive tool, authorised use only.** Rogue AP Hunter is passive and
> read-only: it never captures credentials, never intercepts or decrypts
> traffic, never connects to networks, and never jams, deauthenticates or
> injects anything. It reports **observable metadata patterns**, not proof of
> malicious intent. Use it only on networks and premises you own or have
> explicit permission to assess.

---

## What it does

- Scans through Windows' own `netsh wlan` commands — **two read-only display
  commands**, nothing else.
- Keeps a **trusted-network baseline** (approved SSIDs, approved BSSIDs,
  expected security) that you maintain.
- Runs **six detection rules** — duplicate SSID, unknown BSSID, security
  downgrade, new access point, suspicious signal, persistence — and turns
  them into an **explainable 0–100 risk score** where every point traces back
  to a finding.
- Stores everything **locally** in SQLite (observations, sessions, alerts,
  scores, profiles) with a configurable retention window.
- Optionally adds **passive beacon-frame evidence**: when the free Npcap
  driver is installed, a background observer reads only broadcast
  beacon/probe-response frames (system `wpcap.dll` via ctypes — no extra
  Python packages) and appends observable facts such as *WPS advertised*,
  *802.11w absent*, *hidden SSID* or *SAE advertised* to matching alerts.
  Evidence only — it never changes a risk score.
- Raises **Windows toast notifications** (with a log fallback) and provides a
  full alert workflow: acknowledge → resolve → reopen, plus CSV export.
- Ships a Qt/PySide6 desktop interface with eight screens, background
  monitoring on a configurable interval, and offline operation — no internet
  connection required after installation.

## What it does not do

| Not implemented | |
|-----------------|---|
| Credential capture, interception or decryption | ✗ |
| Packet capture of network traffic, monitor mode, channel hopping | ✗ |
| Auto-connect to observed networks | ✗ |
| Jamming, deauthentication, packet injection | ✗ |
| Cloud services, paid APIs, telemetry | ✗ |

The frame observer mentioned above is deliberately narrower than "packet
capture": it reads only the broadcast management frames an access point
sends in the clear (beacon / probe response — the same class of data `netsh`
reports, plus its information elements). No payload traffic, no client
station addresses, no decryption, no transmission.

Details and the security review: [`SECURITY.md`](SECURITY.md).

## Features

- **Dashboard** — current environment, key counts, most recent alerts.
- **Live networks** — every radio from the last scan, searchable, sortable,
  filterable (All / Unknown / Flagged / Trusted), double-click to investigate.
- **Investigation** — the full reasoning for one identity: reasons,
  security observations, BSSID history, alert history, signal chart.
- **Alerts** — severity/score/type columns, filters, acknowledge / resolve /
  reopen, occurrence tracking, CSV export.
- **Trusted networks** — the approval baseline with per-BSSID allow lists and
  expected security.
- **History** — past scan sessions and stored observations, CSV export.
- **Settings** — scan interval, retention, severity thresholds, risk weights,
  log level, notifications, passive frame observer (with live status) —
  validated before saving.
- **About** — scope, limitations, licence and data locations.

How to read scores and severities:
[`docs/detection-methodology.md`](docs/detection-methodology.md) ·
Screen-by-screen guide: [`docs/user-manual.md`](docs/user-manual.md).

## Requirements

| | |
|---|---|
| Operating system | Windows 10 / 11 (the scanner is `netsh wlan`-based) |
| Python | 3.11+ for development (3.14 used here); packaged builds bundle it |
| Hardware | A wireless adapter with working WLAN support — only needed to *scan*, not to build or test |
| Optional | [Npcap](https://npcap.com) driver for passive beacon-frame evidence; without it the app stays fully netsh-only |
| Network | None — no internet access is required after installation |

## Quick start (development)

```powershell
git clone <repository-url> rogue-ap-hunter
cd rogue-ap-hunter
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Run it:

```powershell
rogue-ap-hunter              # start the graphical interface
python -m app                # equivalent module entry point
rogue-ap-hunter --headless   # initialise config + logging, then exit (code 0)
rogue-ap-hunter --version
rogue-ap-hunter --write-default-config
rogue-ap-hunter --log-level DEBUG      # verbose logging for one run
rogue-ap-hunter --config PATH          # explicit configuration file
```

Exit codes: `0` success · `1` runtime failure · `2` invalid arguments ·
`3` graphical interface unavailable (e.g. PySide6 not installed).

More setup detail: [`docs/setup.md`](docs/setup.md).

## Testing and linting

```powershell
ruff check .              # lint — must stay clean
pytest                    # run the automated test suite
pytest tests/unit         # fast unit tests only
.\scripts\dev-check.ps1   # lint + tests in one step (the pre-commit gate)
```

- The suite currently reports **402 tests passing, 1 environment-skipped**
  (the live frame-capture check skips when Npcap is absent; measured with
  `.\.venv\Scripts\pytest.exe`); see
  [`docs/testing-report.md`](docs/testing-report.md) for the breakdown.
- **Tests never require live Wi-Fi**: scanners are injected, parser input
  comes from sanitized fixtures, GUI tests run on Qt's offscreen platform, and
  live-scan tests skip gracefully when WLAN is unavailable.

## Packaging

```powershell
.\scripts\build.ps1            # onedir build → dist\RogueAPHunter\RogueAPHunter.exe
.\scripts\build.ps1 -Clean     # remove build/ and dist/ first
.\scripts\build.ps1 -OneFile   # single-file executable
```

The script runs `ruff check .` and the full test suite before invoking
PyInstaller (installed into the virtual environment on first use), so a
package is only produced from a passing tree. The executable carries the
application icon (`assets/icon.ico`) and a Windows version resource
(`assets/file_version_info.txt`, kept in sync with `pyproject.toml`).
Build details, the `rogue-ap-hunter.spec` file and verification steps:
[`docs/packaging.md`](docs/packaging.md).

## Where your data lives

All data is local. Default home directory: `%LOCALAPPDATA%\Rogue AP Hunter\`

```
config.json                         settings, thresholds, risk weights
logs\rogue-ap-hunter.log            rotating application log (1 MB × 3 backups)
data\rogue_ap_hunter.sqlite3        observations, sessions, alerts, scores, profiles
```

Set the `ROGUE_AP_HUNTER_HOME` environment variable to relocate everything
(portable mode). CSV exports are written wherever you choose. Nothing is sent
over the network.

## Repository layout

```
rogue-ap-hunter/
├── app/
│   ├── core/        configuration, logging, paths, AppContext wiring
│   ├── scanner/     read-only Windows WLAN scan adapter
│   ├── parser/      defensive parsing of netsh output
│   ├── models/      validated domain objects
│   ├── detection/   detection rules and engine
│   ├── scoring/     explainable risk scoring
│   ├── storage/     SQLite persistence (parameterised SQL, WAL)
│   ├── alerts/      alert lifecycle and notifiers
│   ├── services/    scan pipeline, monitoring loop, views, CSV export
│   └── ui/          PySide6 shell, bridge, theme, pages
├── tests/           unit + integration tests and sanitized fixtures
├── docs/            documentation set (index below)
├── scripts/         dev-check.ps1, build.ps1, benchmark.py, make_icon.py
├── assets/          icons and artwork
├── rogue-ap-hunter.spec   PyInstaller build specification
├── SECURITY.md      security & privacy review
└── pyproject.toml   packaging, dependencies, pytest and ruff configuration
```

## Documentation index

| Document | Contents |
|----------|----------|
| [`README.md`](README.md) | Overview, quick start, commands (this file) |
| [`docs/setup.md`](docs/setup.md) | Developer environment setup, everyday commands, conventions |
| [`docs/user-manual.md`](docs/user-manual.md) | Every screen, alerts workflow, CSV export, keyboard shortcuts, notifications |
| [`docs/developer-guide.md`](docs/developer-guide.md) | Repo layout, architecture layering, how to add a rule/notifier/page, coding standards, test layout |
| [`docs/architecture.md`](docs/architecture.md) | Components, data-flow diagrams, threading model, storage schema, configuration model, exit codes |
| [`docs/detection-methodology.md`](docs/detection-methodology.md) | The six rules and weights, scoring, severity bands, deduplication, false positives, "indicator not proof" |
| [`docs/testing-report.md`](docs/testing-report.md) | Test-suite results, layers, coverage, the no-live-Wi-Fi guarantee |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | netsh/GUI/database/notification/PyInstaller/matplotlib issues, DEBUG logging, log locations |
| [`docs/packaging.md`](docs/packaging.md) | Windows packaging: PyInstaller prerequisites, reproducible build, output, verification |
| [`docs/performance.md`](docs/performance.md) | Measured performance from the offline benchmark harness (`scripts/benchmark.py`) |
| [`docs/quality-audit.md`](docs/quality-audit.md) | Cross-cutting review findings with Fixed / Accepted / Backlog status |
| [`SECURITY.md`](SECURITY.md) | Defensive scope, subprocess/database/file/log review, privacy, responsible use, vulnerability reporting |
| [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) | Licences of every dependency |
| [`DEFENSE_QA.md`](DEFENSE_QA.md) | Anticipated reviewer questions answered from the implementation |
| [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md) | ~15-minute authorised demonstration script |
| [`DEMO_CHECKLIST.md`](DEMO_CHECKLIST.md) | Pre-demo and during-demo tick list |
| [`LICENSE`](LICENSE) | MIT licence text |

## Technology stack

Python 3 · PySide6 (Qt) · `netsh wlan` · SQLite · Matplotlib · pytest · Ruff ·
PyInstaller. Every component is free or open source — see
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md). There is no paid API, no
cloud dependency and no telemetry.

## Responsible use

Test only on networks and equipment you own or are explicitly authorised to
assess. Findings are heuristic indicators based on scan metadata; they do not
establish malicious intent. An alert is a lead for verification, never proof
of an attack. See [`SECURITY.md`](SECURITY.md) §7 and the in-app About screen.

## License

MIT — see [`LICENSE`](LICENSE).
