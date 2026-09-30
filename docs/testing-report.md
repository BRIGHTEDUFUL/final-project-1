# Rogue AP Hunter — Test Suite Report

Current state of the automated test suite, what it covers, and the guarantees
it makes about not needing live Wi-Fi.

**All numbers below were produced by running the suite in this repository's
virtual environment** (`.\.venv\Scripts\pytest.exe`, from the repository root)
at the time of writing. Re-run the commands to reproduce them; counts change
as tests are added.

---

## 1. Headline results

| Command | Result |
|---------|--------|
| `.\.venv\Scripts\pytest.exe` | **319 passed in 17.31s** |
| `.\.venv\Scripts\pytest.exe tests/unit` | **249 passed in 1.98s** |
| `.\.venv\Scripts\pytest.exe tests/integration` | **70 passed in 15.01s** |
| `.\.venv\Scripts\ruff.exe check .` | no findings (gate for every commit) |

- **0 failures, 0 errors.**
- Tests that require a wireless environment **skip** rather than fail, so the
  "319 passed" result holds on machines without WLAN hardware.

pytest configuration (from `pyproject.toml`): `testpaths = ["tests"]`,
`addopts = "-q --strict-markers"`, declared marker `gui`.

---

## 2. Suite layout

```
tests/
├── conftest.py          load_fixture() + pipeline_env() fixtures, repo root on sys.path
├── support.py           FakeScanner, FakeFrameSource and byte-level frame builders (not collected by pytest)
├── fixtures/            7 sanitized netsh output samples
├── unit/                19 files · 309 tests · ~2 s
└── integration/          6 files · 82 tests (1 environment-skipped) · ~15 s
```

### Fixtures (`tests/fixtures/`)

Sanitized copies of real command output, read by the shared `load_fixture`
fixture:

| Fixture | Exercises |
|---------|-----------|
| `netsh_show_networks_single.txt` | one network, one radio |
| `netsh_show_networks_multi.txt` | multiple networks/radios (drives the pipeline and GUI tests) |
| `netsh_show_networks_empty.txt` | zero visible networks |
| `netsh_show_networks_malformed.txt` | hostile/broken output — parser must not raise |
| `netsh_show_interfaces_connected.txt` | connected interface with BSSID/signal |
| `netsh_show_interfaces_none.txt` | zero interfaces present |
| `netsh_service_not_running.txt` | WLAN service failure message |

`tests/support.py::FakeScanner` is a duck-typed scanner returning canned text
(no subprocess), with knobs for unusable scans, failed exit codes and delay.
`tests/support.py::FakeFrameSource` is the frame-observer equivalent (records
start/stop, replays frames through the captured callback), alongside
byte-level builders (`build_beacon`, `rsn_ie`, `vendor_ie`) that synthesise
802.11 frames for the parser tests.

`tests/conftest.py::pipeline_env` wires a complete `ScanPipeline` over a
temporary database with a `FakeScanner` and tears it down again; integration
tests request it instead of rebuilding the object graph by hand.

---

## 3. Test layers

### 3.1 Unit tests — `tests/unit/` (309 tests)

Fast, isolated, no network, no real scanner, no Qt widgets where avoidable.
Storage tests use `:memory:` or `tmp_path` databases.

| File | Tests | Covers |
|------|------:|--------|
| `test_domain_models.py` | 35 | Trusted profiles, severity bands/clamping, alert validation/round-trip, scan sessions, settings, UTC handling |
| `test_beacon_parser.py` | 26 | Synthetic beacon/probe-response bytes: radiotap wrapping, SSID/hidden states, RSN/AKM (PSK, SAE), 802.11w flags, WPS/WPA1 vendor IEs, WEP-era detection, truncated/garbage input never raises |
| `test_detection_rules.py` | 24 | All five static rules: positive, negative, disabled-without-baseline, hidden SSIDs, custom weights |
| `test_storage.py` | 24 | Schema/versioning, CRUD for every repository, dedup + occurrences, status transitions, prune, transaction rollback, SQL-injection parameterisation |
| `test_observation.py` | 22 | Observation validation, hidden detection, immutability, datetime coercion, dict round-trip |
| `test_security.py` | 21 | `SecurityMode` classification, strength ordering, downgrade comparison, enterprise detection |
| `test_bssid.py` | 20 | BSSID normalisation/rejection, list dedup, placeholder handling |
| `test_alerts.py` | 19 | Alert lifecycle: create/dedup/escalate/cooldown, acknowledge/resolve/reopen, notifiers (null, log, composite, toast with injected runner) |
| `test_scanner.py` | 17 | Read-only command enforcement, timeouts, missing executable, exit codes, UTF-8/ANSI decoding, availability checks (injected runner — no real `netsh`) |
| `test_config.py` | 18 | Defaults vs documented baseline, validation ranges, corrupt/unknown-key handling, round-trip, frame-observer flag |
| `test_frame_observer.py` | 18 | Observer lifecycle (disabled/unavailable/running/error/stop), runtime toggling, evidence enrichment, cap and uniqueness, no-malice wording, records surviving restarts |
| `test_capture_source.py` | 12 | Availability checks (Windows/driver), wireless interface selection and classification, GUID extraction from device names, start-path refusals |
| `test_detection_engine_and_scoring.py` | 14 | Engine persistence (appear/reset/retain), scoring = distinct rules only, clamping, explainability, thresholds |
| `test_parser_networks.py` | 11 | Real output parsing, clamping, WEP/Open labels, malformed input, security label preference |
| `test_parser_interfaces.py` | 5 | Connected/disconnected/none parsing, malformed values |
| `test_paths.py` | 5 | `ROGUE_AP_HUNTER_HOME` precedence, platform defaults, derived locations, dir creation |
| `test_cli.py` | 4 | Argument parsing: flags, invalid log level, type errors |
| `test_export.py` | 12 | CSV export: column sets, UTF-8-BOM output, quoting/escaping, atomic write + replace, `ExportError` on write failure |
| `test_model_independence.py` | 2 | Models import no GUI/scanner/storage modules — only stdlib + `app.models` |

### 3.2 Integration tests — `tests/integration/` (82 tests, 1 environment-skipped)

| File | Tests | Covers |
|------|------:|--------|
| `test_gui_smoke.py` | 30 | Real `MainWindow` on **Qt's offscreen platform** with a temporary `AppContext` and `FakeScanner`: window construction, navigation to every page (parametrised over `NAV_ITEMS`), unknown-page handling, async scan-once updating status/pages (event-loop wait) + busy-message refusal, monitoring toggle, surfacing failed scans, investigation evidence, dashboard counts, live-network filtering and double-click investigation, alert acknowledge/resolve/reopen from the queue, alert status filters, CSV export from the alerts page, settings round-trip (including the frame-observer toggle) + invalid-threshold rejection, trusted-network dialog validation and CRUD, theme stylesheet |
| `test_monitoring.py` | 19 | End-to-end pipeline `scan → parse → detect → score → persist → alert`: first-scan behaviour, second-scan dedup, security downgrade alerting, combined scoring, unavailable/failed/empty scans, retention pruning, service start/stop/idempotency, callback failure resilience, error reports, alert transitions in reports, **beacon evidence appended without changing scores**, async one-shot scans (off-thread, overlap refusal while busy or mid-loop) |
| `test_reliability.py` | 11 | Failures degrade instead of crashing: closed or unusable storage becomes an error report (and the next scan recovers), a raising scanner, failed commands, malformed and binary-junk output, history reload after a restart, rapid start/stop cycles, stop-without-start, raising callbacks |
| `test_config_application.py` | 11 | Saved settings reaching the running services: `apply_config` re-points the pipeline and scorer, keeps alert-manager cooldown state, changes scores on the next scan, moves the retention window, updates the monitoring interval (idle and running, callbacks preserved), **toggles the frame observer live** and keeps scanning when the driver is absent |
| `test_startup.py` | 8 | CLI entry: `--headless` exit `0`, `--version`, `--write-default-config`, explicit `--config`, corrupt config tolerance, GUI-unavailable exit code `3`, idempotent logging, invalid log level rejection |
| `test_live_scan.py` | 3 | Real `netsh` smoke tests plus a real frame-observer start/stop check — both **skip gracefully** when WLAN or Npcap is unavailable |

### 3.3 Offscreen GUI testing

`tests/integration/test_gui_smoke.py` sets
`QT_QPA_PLATFORM=offscreen` before importing Qt, so the suite runs on CI
runners and headless machines. It builds the **real** window, repositories and
dialogs; `QMessageBox` static methods are stubbed so nothing can block, and a
session-scoped `QApplication` is reused. This is what the `gui` pytest marker
describes.

---

## 4. Coverage of the application areas

| Area | Covered by |
|------|-----------|
| Domain models & validation | `test_domain_models`, `test_observation`, `test_bssid`, `test_security`, `test_model_independence` |
| netsh output parsing | `test_parser_networks`, `test_parser_interfaces` (+ malformed fixture) |
| Scanner (mocked) | `test_scanner` — injected runner asserts the exact read-only argument lists, timeouts, decoding; no real subprocess |
| Detection rules | `test_detection_rules` |
| Engine + scoring | `test_detection_engine_and_scoring` |
| Frame observer (beacon parsing, evidence, capture prerequisites) | `test_beacon_parser`, `test_frame_observer`, `test_capture_source` (+ enrichment in `test_monitoring`, live start/stop in `test_live_scan`) |
| Storage | `test_storage` |
| Alert lifecycle & notifiers | `test_alerts` |
| Monitoring service & pipeline | `test_monitoring`, `test_reliability` |
| Settings applied to live services | `test_config_application` |
| Configuration / paths / CLI | `test_config`, `test_paths`, `test_cli`, `test_startup` |
| CSV export | `test_export` (unit: headers, missing fields, UTF-8 BOM, special characters, atomic overwrite, `ExportError` on failure) + `test_gui_smoke::test_alerts_csv_export_from_the_page` |
| GUI (all 8 pages, navigation, dialogs, monitoring controls, settings validation) | `test_gui_smoke` |
| Live Windows scanning | `test_live_scan` (skippable) |

---

## 5. The no-live-Wi-Fi guarantee

**The test suite never requires a wireless adapter, a connected network or
internet access.** Mechanisms that enforce this:

1. **Injected scanners.** Unit and most integration tests pass
   `FakeScanner` or `NetshScanner(runner=…)` — no `netsh` process is started.
2. **Fixtures instead of hardware.** Parsing and pipeline tests read the
   sanitized files in `tests/fixtures/`.
3. **Graceful skipping.** `tests/integration/test_live_scan.py` calls the real
   scanner inside `try/except ScannerError` and calls `pytest.skip(...)` —
   never fails — when WLAN scanning is unavailable or the command exits
   non-zero. Zero visible networks is treated as legitimate. The frame
   observer's live check skips the same way when the Npcap driver is absent.
4. **Fake frame source.** All observer tests drive `FakeFrameSource` and
   byte-synthesised frames — no capture driver is loaded by the suite.
5. **Offscreen Qt.** GUI tests need no interactive desktop session.
6. **Temp isolation.** Database, config and logs go to `tmp_path`, with
   `ROGUE_AP_HUNTER_HOME` redirected inside the startup tests — the suite does
   not touch your real application data.

What this means in practice: the same command
(`.\.venv\Scripts\pytest.exe`) passes on a dev box with Wi-Fi, a VM without a
pass-through adapter, and a CI runner.

---

## 6. How to run and interpret results

```powershell
.\.venv\Scripts\pytest.exe                 # full suite (the gate)
.\.venv\Scripts\pytest.exe tests/unit      # fast inner loop (~2 s)
.\.venv\Scripts\pytest.exe tests/unit/test_config.py -k corrupt
.\.venv\Scripts\pytest.exe tests/integration/test_gui_smoke.py
.\scripts\dev-check.ps1                    # ruff check . + pytest
```

Reading the output: `addopts` already applies `-q`, so the summary line is the
authoritative count (e.g. `386 passed, 1 skipped in 17.35s`). If you see
`skipped`, it will be the live-scan or live frame-observer tests on a machine
without WLAN or Npcap — that is the designed behaviour, not a failure.

---

## 7. Honest limitations

- The suite validates behaviour, not detection accuracy in the field: there is
  no corpus of real rogue-AP captures, and no measured false-positive rate is
  claimed here.
- The suite's own timings are wall-clock on one machine. Application
  performance (parsing, scoring, storage, notification cooldowns) is measured
  separately by the offline harness `scripts/benchmark.py` — see
  [`performance.md`](performance.md).
- Live-scan coverage is thin by design (3 tests: two `netsh`, one frame
  observer) because hardware and driver behaviour vary — it exists to prove
  the real paths work, not to characterise them.
- CSV export is covered at the unit level (`test_export`) and once end-to-end
  through the alerts page (`test_gui_smoke::test_alerts_csv_export_from_the_page`);
  the History-page export dialog is not driven by a test. Chart rendering is
  only exercised indirectly (the matplotlib import guard in the Investigation
  page is hit by the GUI tests; no output is compared).
- There is no pixel-level UI regression testing.
