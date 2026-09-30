# Security & Privacy Review — Rogue AP Hunter

This document records how the project handles security and privacy concerns:
what the tool deliberately does **not** do, how it invokes external programs,
how it stores data, what ends up in logs, and how to report a vulnerability.

Version scope: everything below describes the code in this repository as of the
current release (`0.1.0`). Claims here are limited to what the code actually
does — no external certifications or audits are implied.

---

## 1. Defensive scope

Rogue AP Hunter is a **passive, read-only** Wi-Fi monitoring tool for Windows.
Its only data source is the output of two built-in Windows commands:

| Command | Purpose |
|---------|---------|
| `netsh wlan show networks mode=bssid` | List visible networks with per-BSSID detail |
| `netsh wlan show interfaces` | List wireless interfaces and connection state |

Both are display-only commands (see `app/scanner/netsh.py`, `NETWORKS_COMMAND`
and `INTERFACES_COMMAND`). The adapter never invokes any other command, never
modifies network configuration and never connects to a network.

### What the tool explicitly does not do

| Capability | Status | Where this is enforced |
|------------|--------|------------------------|
| Credential collection, capture or storage | **Not implemented** | No code path reads keys, passwords, handshakes or authentication frames. The scanner only parses the text of the two `netsh` display commands. |
| Packet capture (pcap/monitor mode) | **Not implemented** | `app/scanner/` invokes `netsh` only; no capture library is a dependency (`pyproject.toml`: `PySide6`, `matplotlib`). |
| Traffic interception, decryption, man-in-the-middle | **Not implemented** | Nothing in the process touches another device's traffic. |
| Auto-connect to observed networks | **Not implemented** | `netsh` is only ever called with `show` subcommands; there is no connect/disconnect code. |
| Jamming, deauthentication, packet injection, AP mode | **Not implemented** | Requires monitor-mode drivers/injection tooling, none of which is used or depended on. |
| Cloud services, paid APIs, telemetry | **Not implemented** | No network client exists in `app/`; all output is local (log file, SQLite, CSV export, optional Windows toast). |
| Elevating privileges | **Not required** | Scanning via `netsh wlan show` works for a standard user on a machine with WLAN support. |

The same statement is repeated to the user on the in-application **About**
screen (`app/ui/pages/about.py`), so operators see the scope at runtime.

### Input trust model

Output of `netsh` (and of PowerShell for toasts) is treated as **untrusted
text**:

- The parser (`app/parser/`) is defensive: unrecognised lines are ignored,
  missing fields stay `None`, out-of-range values are clamped or dropped and
  malformed output never raises (`tests/unit/test_parser_networks.py`,
  `tests/unit/test_parser_interfaces.py`).
- Nothing from scan output is ever interpolated into another command line or
  into SQL (see §3 and §4).
- Scan output only ever reaches: domain models, the local database, local log
  lines, local UI text and optional desktop toast text.

---

## 2. Subprocess execution review

Two places in the codebase start an external process: the scanner and the
toast notifier. Both were reviewed against the same checklist.

### 2.1 Scanner (`app/scanner/netsh.py`)

- **Fixed argument lists, never a shell.** Commands are declared as frozen
  `ScanCommand` dataclass values (`args` is a tuple). Execution goes through
  `subprocess.run(list(args), capture_output=True, timeout=…, check=False,
  creationflags=CREATE_NO_WINDOW)` — `shell` is never set, so the
  `subprocess.run` default (`shell=False`) applies. The code carries
  `# noqa: S603 - fixed argument list, no shell` documenting the review.
- **Executable resolution.** `netsh` is located with `shutil.which("netsh")`
  at execution time; a missing executable raises `ScannerUnavailableError`
  instead of guessing a path.
- **Timeouts.** Every invocation is bounded by `DEFAULT_TIMEOUT_SECONDS`
  (20.0 s, constructor-overridable, validated positive). A hang becomes
  `ScannerTimeoutError` rather than a stuck monitoring loop.
- **No window.** `CREATE_NO_WINDOW` prevents a console flash and keeps the
  child process invisible to the end user.
- **Output decoding.** Raw bytes are decoded UTF-8 first, then the Windows
  ANSI codepage, then UTF-8 with replacement characters (`_decode`). A single
  odd byte can never crash a scan, and no decoding error is silently ignored
  — the fallback is explicit and tested
  (`test_legacy_codepage_output_falls_back_without_crashing`).
- **Failure surfacing.** Non-zero exits are returned to the caller for
  inspection; timeouts, missing executables and OS errors are converted to
  typed `ScannerError` subclasses and reported as failed scan reports.

### 2.2 Toast notifier (`app/alerts/notifiers.py`)

- **Fixed argument list, never a shell.** PowerShell is started as
  `[powershell, -NoProfile, -NonInteractive, -ExecutionPolicy, Bypass,
  -Command, <static script>]` with `shell` unset (default `False`), again
  annotated `# noqa: S603 - fixed argument list, no shell`.
- **No user data in the command line.** The alert title and message are passed
  to the script through environment variables (`RAPH_TITLE`, `RAPH_MESSAGE`,
  `RAPH_APP_ID`), so SSIDs/BSSIDs containing shell metacharacters cannot be
  interpreted as code.
- **Static script.** `TOAST_SCRIPT` is a module constant; it reads only those
  environment variables and displays a toast.
- **Timeout and failure handling.** 10 s default timeout; `OSError` and
  `subprocess.SubprocessError` are caught and logged, and the method returns
  `False`. A failing notifier never breaks monitoring — `AlertManager` and
  `CompositeNotifier` both catch exceptions and fall back to `LogNotifier`,
  with the in-app alert list always authoritative.

### 2.3 Command inventory

| Process | Started by | Arguments | Timeout | Shell |
|---------|-----------|-----------|---------|-------|
| `netsh wlan show networks mode=bssid` | `NetshScanner.scan` | fixed tuple | 20 s | no |
| `netsh wlan show interfaces` | `NetshScanner.show_interfaces` / `available` | fixed tuple | 20 s | no |
| `powershell` (toast script) | `WindowsToastNotifier.notify` | fixed list + env vars | 10 s | no |

No other `subprocess`, `os.system`, `popen`, `socket` or HTTP client usage
exists in `app/`.

---

## 3. Database access review (`app/storage/`)

- **Parameterised SQL only.** Every statement in
  `app/storage/repositories.py` uses bound parameters (`?`). Where a `WHERE`
  clause is assembled dynamically (filters for SSID/severity/status/date), the
  clause fragments are string literals from code and only the *values* are
  bound. `tests/unit/test_storage.py::test_query_parameterisation_blocks_injection`
  verifies that hostile values are stored and returned verbatim, never
  executed.
- **Transactions and rollback.** Writes go through `Database.transaction()`,
  which rolls back on error and re-raises as `StorageError`; a rollback test
  exists (`test_transaction_rolls_back_on_failure`).
- **Connection policy.** One connection per process, guarded by a
  `threading.RLock`, with `check_same_thread=False` justified by that lock:
  the monitoring thread and the Qt UI thread never run long transactions and
  SQLite serialises writes. `PRAGMA foreign_keys = ON`,
  `PRAGMA journal_mode = WAL`, `PRAGMA busy_timeout = 5000` and a 10-second
  connect timeout are set at open time.
- **Local-only path.** The database file lives under the per-user application
  directory: `<home>/data/rogue_ap_hunter.sqlite3`, where `<home>` is
  `%LOCALAPPDATA%\Rogue AP Hunter` by default or the value of
  `ROGUE_AP_HUNTER_HOME` (`app/core/paths.py`). When an explicit `--config`
  path is given, the database is placed in `<config dir>/data/`. There is no
  configuration that points the database at a network share or remote host,
  and no code path opens any other database file.
- **Schema migrations** run inside one transaction and are version-stamped in
  `schema_meta` (`app/storage/schema.py`, `SCHEMA_VERSION`).
- **Retention.** Observations, non-active alerts and score history are pruned
  to `data_retention_days` (default 90) every 20 scans.

---

## 4. File handling review

| File | Writer | Safety property |
|------|--------|-----------------|
| `<home>/config.json` | `save_config` (`app/core/config.py`) | Validated first, written to a `.tmp` sibling, then atomically `Path.replace`d over the target. A crash cannot leave a half-written config. |
| `<home>/data/rogue_ap_hunter.sqlite3` | `sqlite3` via `Database` | Standard SQLite journaling/WAL; parent directory created on demand. |
| `<home>/logs/rogue-ap-hunter.log` | `RotatingFileHandler` | 1 MB cap, 3 backups, UTF-8; failure to open the directory disables file logging with a warning instead of crashing (`app/core/logging_setup.py`). |
| CSV export | `app/services/export.py` | UTF-8 **with BOM** (`utf-8-sig`) for spreadsheet compatibility, written to a `.tmp` file and atomically replaced; on error the temporary file is removed and `ExportError` is raised — no truncated exports. |

**Per-user data directory.** Every default location derives from
`app.core.paths.app_home()`, which resolves, in order:

1. `ROGUE_AP_HUNTER_HOME` (portable installs, tests) — relocates *everything*;
2. `%LOCALAPPDATA%\Rogue AP Hunter` on Windows;
3. `$XDG_DATA_HOME/rogue-ap-hunter` or `~/.local/share/rogue-ap-hunter` elsewhere.

No absolute path is hard-coded anywhere in `app/`; paths are resolved through
`app.core.paths` only (enforced by convention and by `tests/unit/test_paths.py`).
The only files written outside the home directory are the configuration file
when `--config` is used explicitly and CSV files the operator picks in the
save dialog.

---

## 5. Log content policy

Logging is local-only and configured in `app/core/logging_setup.py`
(format `%(asctime)s %(levelname)-8s %(name)s: %(message)s`).

**What is written:**

- Scan outcomes: network/finding/alert counts, durations, scanner errors.
- Detection results: rule names, SSIDs, BSSIDs, risk scores, severities and
  human-readable reasons (e.g. `new alert duplicate_ssid for Corp [aa:bb:…]`).
- Alert notification payloads (via `LogNotifier`, at `WARNING`).
- Truncated command failures: at most the first 200 characters of
  `stderr`/`stdout` (`RawScanResult.summary`).

**What is never written:**

- Credentials, passwords, pre-shared keys, handshakes or any traffic content —
  the tool never collects them (§1), so they cannot reach the log.
- Environment dumps, tokens or configuration secrets (the configuration file
  contains only scan/threshold/weight/retention settings).
- Full packet or frame data — no capture exists.

**Honest caveat:** SSIDs and BSSIDs *are* network identifiers and are logged at
`INFO`/`WARNING` for operational usefulness. In some organisations SSIDs are
considered sensitive (site names, tenant names). Treat log files, the SQLite
database and CSV exports as potentially sensitive operational data: keep them
under the per-user profile, and redact before sharing in bug reports.

**Log levels.** `INFO` by default; run with `--log-level DEBUG` for verbose
diagnostics (see `docs/troubleshooting.md`).

---

## 6. Privacy summary

- **No data leaves the machine.** There is no telemetry, crash reporting,
  update check or remote API call anywhere in `app/`.
- **What is stored locally:** observations (SSID/BSSID/signal/security/
  channel/timestamps), scan sessions, trusted-network profiles you enter,
  alerts with their reasons and scores, risk-score history, and `config.json`.
- **Who can read it:** anything running as your user account. The data
  directory inherits normal per-user filesystem permissions.
- **How to erase it:** delete the application home directory, or set
  `ROGUE_AP_HUNTER_HOME` to a scratch location and delete that.
- **Desktop notifications:** alert title/evidence text is passed to the local
  Windows notification service via environment variables of a child PowerShell
  process; it is not sent to any third party by this application.

---

## 7. Responsible use

- Use Rogue AP Hunter **only** on networks and premises you own or have
  explicit, documented permission to assess. Unauthorised monitoring of other
  people's networks may be illegal in your jurisdiction.
- Findings are heuristic indicators derived from scan metadata. **An alert is
  an indicator to verify, never proof of malicious activity.** Act only
  against equipment you are authorised to touch.
- The tool does not disrupt service. Do not combine it with tools that do
  (deauthentication, jamming) — that is outside this project's scope and may
  be unlawful.
- When sharing results (screenshots, CSV exports, logs), review SSIDs/BSSIDs
  for organisational sensitivity first.

---

## 8. Known limitations

Stated plainly so nobody mistakes this tool for a complete security product:

- **Heuristic detection.** Rules describe observable patterns only; there is
  no cryptographic validation of an access point, no 802.11 management-frame
  analysis and no WIPS functionality.
- **Data source limits.** Detection quality depends on what the local adapter
  reports through `netsh` (scan cadence, band support, driver behaviour).
  Hidden SSIDs and partially reported BSSIDs reduce visibility.
- **Single-user, single-machine.** No multi-tenant access control, no
  encryption at rest beyond what the filesystem provides, no authentication.
- **No update mechanism.** The application does not check for or install
  updates.
- **Baseline trust.** Anyone who can edit `config.json` or the trusted-network
  table can change what counts as "normal"; protect the user profile.

---

## 9. Reporting a vulnerability

We welcome responsible disclosure of security or privacy issues in Rogue AP
Hunter (for example: command injection via crafted scan output, SQL injection,
path traversal in config/export handling, sensitive data in logs, or an
unexpected network egress).

**How to report**

1. Prefer the hosting platform's **private vulnerability reporting** /
   "Security advisory" feature for this repository (it keeps the report off
   the public issue tracker).
2. If that is unavailable, open a normal issue titled
   `SECURITY: <short summary>` **without** exploit details and ask for a
   private contact channel, or contact the maintainers listed in the
   repository metadata.
3. Include: affected version/commit, affected OS version, steps to reproduce,
   expected vs. actual behaviour, potential impact, and any suggested fix.

**What to expect**

- Acknowledgement when a maintainer reads the report (target: within 7 days).
- A fix or a documented mitigation before public detail, with a typical
  **90-day** coordinated disclosure window (shorter if a fix lands sooner,
  longer if we mutually agree).
- Credit in the release notes if you want it.
- Reports made in good faith will not result in legal action from this
  project.

**Out of scope:** issues that require unprotected Wi-Fi networks or third-party
infrastructure, social-engineering of other users, denial-of-service against
networks you do not own, and "the tool detected my own test AP incorrectly"
tuning questions (those are documentation/detection-quality issues — file them
as regular issues).
