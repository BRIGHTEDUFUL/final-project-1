# Quality Audit — Prompt 24

Role: senior cybersecurity software reviewer. Scope: requirements
completeness, architecture, security, privacy, free-only technology, testing,
false-positive handling, explainability, UI usability, documentation and
academic defensibility. Method: full source review plus an executed
verification pass (`ruff check .`, `pytest`, `scripts/build.ps1`).

Status legend: **Fixed** (issue corrected, regression test added),
**Accepted** (kept deliberately, rationale recorded), **Backlog** (justified
but not required for this release).

---

## 1. Prioritized issue list

### P1 — correctness / safety impact

| # | Issue | Status | Evidence |
| --- | --- | --- | --- |
| 1 | **Saved settings never reached the running pipeline.** `AppContext.apply_config` replaced `context.engine`/`context.scorer`, but `ScanPipeline` kept the objects built at construction: weights, thresholds and the retention window silently stayed at old values until restart. The Settings screen therefore lied to the operator. | **Fixed** — `ScanPipeline.apply_config()` now pushes config, scorer and alert manager into the live pipeline; context exposes the exact objects the scans use. | `tests/integration/test_config_application.py` (9 tests, incl. end-to-end "lowering a weight lowers real scores") |
| 2 | **`ScanPipeline.run()` could raise**, violating its own "never raises" contract: `self._sessions.start()` ran outside the `try`, so a storage failure escaped into the monitoring loop or a GUI slot. | **Fixed** — session creation is guarded; failure yields an in-memory FAILED report. | `test_closed_database_becomes_error_report`, `test_storage_failure_does_not_poison_the_next_scan` |
| 3 | **CSV export raised raw `OSError`.** `path.parent.mkdir(...)` sat outside the guarded block, so a read-only or file-occupied parent bypassed `ExportError` — the Alerts/History handlers catch `ExportError` only, leaving a traceback and no user message. | **Fixed** — mkdir moved inside the try; temp cleanup made best-effort so it cannot mask the original error. | `test_unwritable_parent_raises_export_error_not_oserror`, 12 export tests total |

### P2 — misleading behaviour / integrity

| # | Issue | Status | Evidence |
| --- | --- | --- | --- |
| 4 | **`_fail()` returned a stale session.** The FAILED status was persisted, but the report handed to the UI carried the pre-failure `RUNNING` session — History would show a failed scan as still running. | **Fixed** — `_fail()` uses the finished session (model fallback when storage is down). | `test_raising_scanner_becomes_error_report` |
| 5 | **Config save reset notification state.** `apply_config` rebuilt `AlertManager`, discarding the per-identity 60-second cooldown map (an escalation right after a settings save could re-notify). The rebuild also achieved nothing — `AlertManager` reads no live setting from that config object. | **Fixed** — in-place `AlertManager.apply_config()`; the same manager instance survives configuration changes. | `test_save_config_keeps_alert_manager_state` |
| 6 | **Interval change ignored while monitoring was stopped** — the stopped `MonitoringService` kept its old cadence, so *Start monitoring* after a settings change used the previous interval. | **Fixed** — the service is rebuilt (callbacks preserved) whenever the interval changes, running or not. | `test_save_config_updates_idle_monitoring_interval` |

### P3 — polish / packaging

| # | Issue | Status | Evidence |
| --- | --- | --- | --- |
| 7 | About screen showed `0.1.0+dev` (or worse, stale package metadata) inside packaged builds. | **Fixed** — frozen builds report the source version (`sys.frozen` branch). | `app/ui/pages/about.py`; verified in the built exe (`--version` → `0.1.0`) |
| 8 | `tests/conftest.py` imported `tests.support` before inserting the repo root into `sys.path` (import error when running a single test file). | **Fixed** — path bootstrap precedes imports. | whole suite runs from any invocation |
| 9 | Theme stylesheet used `%` formatting (lint: UP031) and an early draft had a corrupted hex literal. | **Fixed** — placeholder substitution; visual sanity via offscreen GUI tests. | `test_stylesheet_contains_core_rules` |
| 10 | Leftover broken placeholder module in the UI package during development. | **Fixed** — removed before commit. | commit `bb04f4c` review |

### Earlier-phase defects (found and fixed during construction)

Uppercase-hex BSSID normalization failure; dict-assignment on a slotted
dataclass inside the parser; malformed MAC crashing a whole parse; garbage
labels overwriting signal/channel; a docstring tripping the model-independence
guard; several fixture/expectation errors. Each fix is covered by the unit
tests listed in `docs/testing-report.md`.

### Accepted limitations (deliberate)

| Item | Rationale |
| --- | --- |
| *Scan once* runs on the GUI thread | ✅ fixed — *Scan once* now submits `scan_once_async()` to a daemon thread; the button is disabled until the report arrives through the bridge, and overlapping submissions are refused (`test_scan_once_async_*`, `test_scan_once_shows_busy_message_*`). |
| Notification cooldown lives in memory | resets on restart by design (never persist "do not disturb" state); worst case is one repeated toast after a restart. |
| No code signing / no icon / no version resource | free-only constraint: no certificates or proprietary tooling. Documented with a SmartScreen workaround in `docs/packaging.md`. |
| English `netsh` label dependence | parser is tolerant and fixture-tested; non-English Windows is a documented limitation, not a silent failure (unknown labels degrade, they do not corrupt — see malformed fixtures). |
| `_last_notified` / `_known_bssids` grow monotonically | bounded by the number of distinct identities observed (verified in `docs/performance.md`, 300-scan run: ~6 KiB RSS per scan). |
| Visual/pixel regression testing absent | offscreen smoke tests assert structure and behaviour, not rendering; acceptable for a dark-themed utility UI. |
| Heuristic detection cannot attribute intent | inherent to passive observation; addressed by language review (never claims malice) and by `docs/detection-methodology.md`. |

---

## 2. Requirements completeness (Definition of Done mapping)

| Requirement | Verdict | Where |
| --- | --- | --- |
| All major requirements implemented and tested | ✅ | 313 tests, 0 failed; `ruff` clean |
| No paid APIs or services | ✅ | dependencies: PySide6, matplotlib, stdlib SQLite; notifications via local PowerShell toast; no network client code exists |
| Works offline | ✅ | only local `netsh` execution + local files; verified in packaged build with no network assumptions |
| Detection is explainable | ✅ | per-scan reason strings persisted with every score; Investigation screen surfaces them |
| False positives considered | ✅ | baseline/mesh/hidden/first-scan/persistence mitigations; `docs/detection-methodology.md` |
| Alerts persist | ✅ | SQLite (WAL), dedupe/occurrence/escalation history survive restart — `test_restart_reloads_history…` |
| UI remains responsive | ✅ | monitoring on worker thread, queued signals; measurements in `docs/performance.md` |
| Packaging reproducible | ✅ | `scripts/build.ps1` = lint → tests → PyInstaller; `docs/packaging.md` |
| Third-party licences documented | ✅ | `THIRD_PARTY_LICENSES.md` bundled into the build |
| User + developer documentation complete | ✅ | README, setup, user manual, developer guide, architecture, methodology, testing report, security, troubleshooting, packaging, performance |
| Safe, authorised demonstration possible | ✅ | `DEMO_SCRIPT.md`, `DEFENSE_QA.md`, `DEMO_CHECKLIST.md` + fixture-only fallback |

## 3. Security & privacy review summary

* **No offensive capability**: scanner executes a fixed argument list with
  `shell=False`, timeout, and no write operations; no deauth/jam/inject/
  capture/connect code exists anywhere in `app/`.
* **No credential handling**: the application never asks for, reads, stores
  or transmits credentials; logs contain no secrets (log review in
  `SECURITY.md`).
* **Data localisation**: config/log/db under the per-user app directory only;
  CSV export requires an explicit user path choice.
* **Injection surfaces**: subprocess arguments are static; the PowerShell
  toast path passes values via environment variables (no string interpolation
  into a command line); SQL is fully parameterized (repo review + tests).
* **Fail-closed behaviour**: storage/notification/scanner failures degrade to
  logged errors; no silent `except: pass` exists (verified by review; every
  `except Exception` logs with `logger.exception` or converts to a typed
  error).

## 4. Documentation review

Documentation is code-derived (no invented APIs or numbers): the testing
report quotes the executed suite, the performance document quotes measured
runs on the stated hardware, and the packaging guide quotes verified commands.
`README.md` links every document; demo documents link back to methodology and
security.

## 5. Verdict

**Ship for authorised evaluation.** Three P1 issues (settings not applied,
storage failures escaping the pipeline, export errors bypassing the UI) and
three P2 issues were found in this audit and fixed with regression tests; the
remaining items are accepted trade-offs of a free, offline, passive-only tool
and are documented where a user or reviewer would look for them.
