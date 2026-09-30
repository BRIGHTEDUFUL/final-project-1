# Rogue AP Hunter — Developer Guide

How the repository is laid out, how to set up a development environment, the
commands that gate every commit, how the layers fit together, and how to make
common changes (new detection rule, new notifier, new screen).

For a component/data-flow view see [`architecture.md`](architecture.md); for
the test suite see [`testing-report.md`](testing-report.md); for environment
setup details see [`setup.md`](setup.md).

---

## 1. Repository layout

```
rogue-ap-hunter/
├── app/                      application package (installed; not a script folder)
│   ├── __main__.py           `python -m app` entry point
│   ├── main.py               CLI parsing, exit codes, startup wiring
│   ├── core/
│   │   ├── config.py         Config/RiskWeights dataclasses, JSON load/save
│   │   ├── context.py        AppContext — the single wiring point for subsystems
│   │   ├── logging_setup.py  console + rotating file logging
│   │   └── paths.py          ROGUE_AP_HUNTER_HOME-derived locations
│   ├── scanner/              read-only `netsh wlan` adapter (+ typed errors)
│   ├── parser/               defensive parsing of netsh output
│   ├── models/               domain objects (observation, alert, trusted, …)
│   ├── detection/            DetectionContext, rules, DetectionEngine
│   ├── scoring/              RiskScorer → explainable 0–100 scores
│   ├── storage/              SQLite Database, schema/migrations, repositories
│   ├── alerts/               AlertManager lifecycle + notifiers
│   ├── services/             ScanPipeline, MonitoringService, views, CSV export
│   └── ui/                   PySide6 shell, bridge, theme, widgets, pages/
├── tests/
│   ├── conftest.py           sys.path + `load_fixture` and `pipeline_env` fixtures
│   ├── support.py            FakeScanner and other helpers (not collected)
│   ├── fixtures/             sanitized netsh output samples (*.txt)
│   ├── unit/                 fast, dependency-free tests
│   └── integration/          pipeline, startup, monitoring, GUI smoke, live scan
├── scripts/
│   ├── dev-check.ps1         lint + tests (the pre-commit gate)
│   ├── build.ps1             PyInstaller packaging (runs ruff + pytest first)
│   └── benchmark.py          offline benchmark harness (see docs/performance.md)
├── docs/                     this documentation set (index in README.md)
├── assets/                   icons and static artwork
├── pyproject.toml            metadata, dependencies, pytest + ruff config
├── rogue-ap-hunter.spec      PyInstaller build specification
├── SECURITY.md               security & privacy review
├── THIRD_PARTY_LICENSES.md   dependency licences
└── LICENSE                   MIT
```

---

## 2. Environment setup

Prerequisites: **Windows 10/11**, **Python 3.11+** (development here uses
3.14), Git. A wireless adapter is *not* required to build or test the project.

```powershell
git clone <repository-url> rogue-ap-hunter
cd rogue-ap-hunter
python -m venv .venv
.venv\Scripts\Activate.ps1          # PowerShell (or .venv\Scripts\activate.bat)
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Runtime dependencies (from `pyproject.toml`): `PySide6>=6.6`, `matplotlib>=3.8`.
Development extras: `pytest>=8.0`, `ruff>=0.6`.

Verify:

```powershell
rogue-ap-hunter --version
python -c "import PySide6, matplotlib; print('deps ok')"
```

If you prefer not to activate the virtual environment, call the tools by path:
`.\.venv\Scripts\python.exe -m pytest`, `.\.venv\Scripts\ruff.exe check .`.

---

## 3. Commands

| Task | Command |
|------|---------|
| Run the GUI | `rogue-ap-hunter` or `python -m app` |
| Headless initialisation check | `rogue-ap-hunter --headless` |
| Lint (must stay clean) | `ruff check .` |
| Auto-fix lint findings | `ruff check --fix .` |
| Format | `ruff format .` |
| Tests | `pytest` (or `.\.venv\Scripts\pytest.exe`) |
| Unit tests only (fast) | `pytest tests/unit` |
| Single test | `pytest tests/unit/test_config.py::test_defaults_are_valid` |
| Lint + tests in one step | `.\scripts\dev-check.ps1` |
| Package a Windows build | `.\scripts\build.ps1` (runs ruff + pytest, then PyInstaller) |
| Offline benchmark | `.\.venv\Scripts\python.exe scripts\benchmark.py --iterations 20 --scans 50` |

`pyproject.toml` configures pytest (`testpaths = ["tests"]`,
`addopts = "-q --strict-markers"`, marker `gui`) and ruff (line length 100,
`target-version = "py311"`, rules `E, F, W, I, UP, B, C4`, `E501` ignored,
first-party module `app`).

**Quality gate:** `ruff check .` must report no errors and `pytest` must pass
before every commit. `scripts/dev-check.ps1` runs exactly that sequence.

---

## 4. Architecture: layering and data flow

The pipeline is strictly one-directional:

```
scanner  →  parser  →  storage  →  detection  →  scoring  →  alerts  →  monitoring service  →  Qt UI
(netsh)     (text)     (SQLite)    (findings)    (0–100)    (lifecycle)   (background loop)   (MonitorBridge)
```

| Layer | Package | Responsibility |
|-------|---------|----------------|
| Scanner | `app/scanner` | Run the two read-only `netsh wlan` commands; return raw text + metadata. Never interprets results. |
| Parser | `app/parser` | Turn text into `NetworkObservation` / `InterfaceInfo`. Defensive: unknown lines ignored, missing fields `None`, never raises. |
| Storage | `app/storage` | Parameterised SQLite persistence for sessions, observations, trusted profiles, alerts, scores, settings. |
| Detection | `app/detection` | Pure rules over a `DetectionContext`; `DetectionEngine` adds cross-scan persistence state. |
| Scoring | `app/scoring` | `RiskScorer` sums distinct-rule weights, clamps to 0–100, attaches reasons and severity. |
| Alerts | `app/alerts` | `AlertManager` records occurrences, deduplicates, acknowledges/resolves, and notifies. |
| Services | `app/services` | `ScanPipeline` (one synchronous end-to-end pass), `MonitoringService` (background loop), views and CSV export. |
| UI | `app/ui` | PySide6 pages; consumes callbacks through `MonitorBridge` signals. |

Wiring lives in **one place**: `AppContext` (`app/core/context.py`). The UI
never instantiates repositories or the scanner itself; tests build the same
object graph with a temporary database and a `FakeScanner`.

Rules of the layering:

- Lower layers never import from higher ones (domain `models/` import nothing
  outside the standard library — enforced by
  `tests/unit/test_model_independence.py`).
- The scanner does not parse, the parser does not store, storage does not
  detect.
- `ScanPipeline.run()` is synchronous and side-effect-complete: scan → parse →
  detect → score → persist → alert, and it never raises — failures become
  error `ScanReport`s.

### Threading in one paragraph

`MonitoringService` runs a daemon worker thread (`rogue-ap-monitor`) that scans
immediately on start and then waits `interval` seconds between passes;
`start()`/`stop()` are guarded by a lifecycle lock and `stop()` joins the
thread (10 s timeout). Callbacks execute **on the worker thread**. The UI
passes `MonitorBridge.emit_report` / `emit_error` as those callbacks; Qt's
queued cross-thread signal delivery runs the matching slots
(`MainWindow._on_report`, `_on_error`) on the GUI thread. Never touch widgets
from a monitoring callback — emit a signal instead.

---

## 5. How to add things

### 5.1 A new detection rule

1. **Weight** — add a field to `RiskWeights` in `app/core/config.py` with its
   default. `Config.validate()` already range-checks every weight field.
   (Existing tests asserting documented defaults may need the new default.)
2. **Rule identity** — add the value to `FindingRule`
   (`app/detection/findings.py`) **and** to `AlertType`
   (`app/models/alert.py`). They must match: `ScanPipeline` maps the dominant
   finding's `rule.value` to `AlertType(...)` and falls back to `OTHER` on
   mismatch.
3. **Rule function** — implement it in `app/detection/rules.py` with the shape
   `def my_rule(context: DetectionContext, weights: RiskWeights) -> list[Finding]`.
   It must be **pure**: read `context` only, never mutate state, never claim
   malice — `Finding.explanation` states what was observed, `Finding.evidence`
   carries the data an operator can verify.
4. **Registration** — append it to `all_rules()` so it runs in the stable
   order.
5. **Settings UI** — add a caption to `_WEIGHT_FIELDS` in
   `app/ui/pages/settings_page.py` so the weight is editable.
6. **Tests** — add positive/negative cases in
   `tests/unit/test_detection_rules.py`, plus an end-to-end case in
   `tests/integration/test_monitoring.py` if the rule needs scan history.

### 5.2 A new notifier

1. Implement the `Notifier` protocol from `app/alerts/notifiers.py`:
   `def notify(self, alert: Alert) -> bool` — return `True` only when delivery
   succeeded.
2. Never raise for expected failures (missing tool, permission denied):
   log and return `False`. If you must raise, ensure the chain catches it —
   `CompositeNotifier` and `AlertManager._maybe_notify` already do.
3. Add it to the chain in `default_notifier()` (`app/core/context.py`),
   ordered before `LogNotifier` so the log remains the final fallback.
4. Tests belong in `tests/unit/test_alerts.py`; inject a fake `runner`
   instead of starting real processes (see `WindowsToastNotifier`'s
   `runner` parameter for the pattern).

### 5.3 A new screen (page)

1. Create `app/ui/pages/my_page.py`, subclassing `Page`
   (`app/ui/pages/base.py`). Implement `refresh()` (reload from storage) and,
   optionally, `on_scan_report(report)` for automatic refresh after scans.
2. Add the `(key, label)` entry to `NAV_ITEMS` in `app/ui/shell.py` — the
   sidebar button is created from it automatically.
3. Instantiate the page in `MainWindow.__init__`, add it to `self._pages`, and
   add the widget to `self._stack` (keep the loops/dicts consistent with the
   nav order).
4. Wire any cross-page signals in the shell (the existing pattern is
   `open_investigation = Signal(object, object)` consumed by
   `MainWindow.open_investigation`).
5. If the page needs data, access it through `AppContext` repositories —
   never open the database directly from UI code.
6. Tests: `tests/integration/test_gui_smoke.py` parametrises navigation over
   `NAV_ITEMS`, so your new page is smoke-tested automatically; add
   page-specific assertions alongside.

---

## 6. Coding standards

- **Type hints** on every function signature (public and private).
- **Docstrings** for anything non-obvious; module docstrings state intent and
  constraints. Keep the existing tone: plain, factual, no marketing.
- **No silent exception swallowing.** Either handle with context
  (`logger.exception("…")` plus a user-visible fallback) or propagate. Broad
  `except Exception` is acceptable only in defensive boundaries (monitoring
  callbacks, closing resources) where it is always logged.
- **No hard-coded paths.** Resolve locations through `app.core.paths`
  (`ROGUE_AP_HUNTER_HOME`-aware). Tests use `tmp_path`.
- **No shell strings.** External programs are started with fixed argument
  lists and `shell` unset; document the review in a `# noqa: S603` comment if
  ruff flags it.
- **Parameterised SQL only.** Never format user values into SQL text.
- **Frozen dataclasses / immutable models** unless mutation is required and
  documented.
- **Tests must not need live Wi-Fi.** Inject scanners (`FakeScanner`,
  `NetshScanner(runner=...)`) and read from `tests/fixtures/`. Live tests skip
  gracefully via `pytest.skip`.
- **Only free/open-source dependencies.** Add them to `pyproject.toml` and
  `THIRD_PARTY_LICENSES.md` in the same commit.
- **Line length 100**, import order enforced by ruff's isort rules
  (first-party: `app`).

---

## 7. Test layout

```
tests/
├── conftest.py                 load_fixture() → reads tests/fixtures/<name>
│                               pipeline_env → full pipeline over a temporary
│                               database with FakeScanner (shared by integration tests)
├── support.py                  FakeScanner (canned netsh text, no subprocess)
├── fixtures/                   netsh_show_networks_{single,multi,malformed,empty}.txt
│                               netsh_show_interfaces_{connected,none}.txt
│                               netsh_service_not_running.txt
├── unit/                       models, parser, scanner (mocked runner), detection,
│                               scoring, storage, alerts, config, paths, CLI,
│                               CSV export
└── integration/                startup (exit codes, logging), monitoring pipeline
                                lifecycle, settings-apply and reliability failures,
                                GUI smoke (QT_QPA_PLATFORM=offscreen),
                                live scan (skips when WLAN unavailable)
```

Conventions:

- Unit tests import only `app.*` and `tests.support`; they run in seconds and
  touch only `tmp_path`.
- Integration tests that need a wired pipeline should request the shared
  `pipeline_env` fixture instead of rebuilding the object graph; it opens a
  temporary database, injects `FakeScanner`, and closes everything afterwards.
- GUI tests set `QT_QPA_PLATFORM=offscreen`, build the real `MainWindow`
  against a temporary `AppContext`, and stub out `QMessageBox` so nothing
  blocks headless.
- The `gui` pytest marker exists for tests needing a Qt-capable environment.
- Fixtures are sanitized copies of real `netsh` output — never edit them to
  make a test pass without checking what Windows actually emits.

Current suite size and per-file breakdown: see
[`testing-report.md`](testing-report.md).

---

## 8. Git workflow

```powershell
git checkout -b feature/<short-name>
git add <explicit paths>
git commit -m "<area>: what changed and why"
```

- Stage explicit paths; avoid `git add -A` so unrelated work is never swept
  into a commit.
- Keep commits scoped: code + its tests + the docs that describe it.
- `scripts/dev-check.ps1` must pass before pushing.
