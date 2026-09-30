# Rogue AP Hunter — Troubleshooting

Common problems, what the error actually means, and the fix. Commands are
shown for PowerShell from the repository root; the packaged executable behaves
the same way.

---

## 0. First stops

1. **Read the status bar.** Failed scans appear there as
   `Scan failed: <reason>` for 10 seconds without interrupting you.
2. **Read the log.** Every issue below leaves a trail:
   `from app.core import paths; paths.log_file()` →
   `%LOCALAPPDATA%\Rogue AP Hunter\logs\rogue-ap-hunter.log`
   (see §9 for DEBUG mode and rotation details).
3. **Check the exit code** when a command-line run fails:

   | Code | Meaning | Jump to |
   |-----:|---------|---------|
   | `0` | Success | — |
   | `1` | Runtime failure (storage, directories, unhandled error) | §4 |
   | `2` | Invalid arguments | §10 |
   | `3` | Graphical interface unavailable | §3 |

---

## 1. `netsh` failures / no wireless interface

**Symptoms**

- Status bar: `Scan failed: wireless scanning unavailable: …`
- Log: `scanner failure: …`, `scan command reported an error: …`
- Or: `the 'netsh' command was not found on this system; Wi-Fi scanning
  requires Windows with WLAN support`
- Or: `no wireless interfaces are present on this system`

**What it means.** The scanner runs only
`netsh wlan show networks mode=bssid` and `netsh wlan show interfaces`
(read-only). The pipeline first asks `NetshScanner.available()`; if that says
"unusable", the scan is recorded as a **failed session** and no observations
are stored — this is normal behaviour, not a crash.

**Fixes**

```powershell
netsh wlan show drivers      # does Windows see a WLAN driver at all?
netsh wlan show interfaces   # is an interface present and its state?
```

| Check | Action |
|-------|--------|
| `netsh` itself is missing | You are not on Windows, or the system is badly damaged — this tool targets Windows 10/11. |
| "There are 0 interfaces on the system" | No wireless adapter: enable it in Device Manager, plug in the Wi-Fi dongle, or re-enable it (`devmgmt.msc` → Network adapters → Enable device). |
| Interface exists but the command fails | The **WLAN AutoConfig service** (`wlansvc`) is stopped or disabled: `Get-Service WlanSvc` → `Start-Service WlanSvc`. |
| Command hangs then times out | A 20-second timeout turns this into `… scan exceeded the 20s timeout`. Restart `WlanSvc` and the adapter; check for vendor driver issues. |
| Output looks garbled | Not fatal: decoding falls back UTF-8 → Windows ANSI → replacement characters. If fields parse as `—`, confirm the console codepage with `chcp`. |
| Airplane mode / disabled radio | Turn the radio back on (physical switch, `Fn` key, or Settings → Network → Wi-Fi). |

Monitoring keeps retrying every scan interval, so once the adapter is back the
next pass recovers automatically. The **Dashboard → Current environment**
panel shows the interface state after a successful scan.

### Non-English Windows output

`netsh` localises its labels (`Autenticación` instead of `Authentication`,
`Kanal` instead of `Channel`, `Estado` instead of `State`, …). The parsers
recover what translates safely, by **value shape**:

| Recovered by shape | Why it is safe |
|--------------------|----------------|
| BSSID / MAC addresses | `aa:bb:cc:dd:ee:ff` looks the same in every language |
| Signal percentage | a bare `87 %` inside a radio block is always the signal |
| Channel number | a bare integer inside a radio block is always the channel |
| Connected interface | netsh reports a BSSID only while connected, whatever the state label says |

What cannot be recovered by shape is the **security label**. When none of
the frequently translated labels (`Authentication`, `Encryption`,
`Channel`) match their English aliases, the scan still succeeds but the
status bar appends an honest warning:

```text
4 networks, 0 findings, 0 new alerts in 0.42s · netsh returned network
details with unrecognised labels (non-English Windows output); security
details may be incomplete — see docs/troubleshooting.md
```

The same line is written to the log at `WARNING` level. Security fields
then display as `—` instead of being guessed, and rules that compare
security labels (for example the security-downgrade rule) cannot fire until
labels parse; SSID/BSSID based detection, history and alerts are unchanged.
The warning never fires on English output — the detection is conservative
by design (fixture-tested both ways: `netsh_show_networks_localized_es.txt`
warns, every English fixture stays silent).

---

## 2. The application will not start (general)

| Symptom | Cause | Fix |
|---------|-------|-----|
| `'rogue-ap-hunter' is not recognized` | Virtual environment not active | Activate it (`.venv\Scripts\Activate.ps1`) or run `python -m app` with `.venv\Scripts\python.exe` |
| Exit code `2`, usage message | Wrong/unknown flag or `--log-level` value | Run `rogue-ap-hunter --help`; valid levels are `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| Exit code `1`, `Local storage could not be opened` | SQLite cannot open/create the database file | See §4 |
| Exit code `1`, `Application directories could not be prepared` | The data home cannot be created (permissions, read-only/synced location) | See §4 |
| Window opens then closes, log shows `Unhandled error while running the graphical interface` | Exception during UI startup | Re-run with `--log-level DEBUG`, check the traceback in the log, and report it (see `SECURITY.md` §9 for security-relevant issues) |

A corrupt `config.json` does **not** prevent startup: the log records
`Configuration could not be loaded (…); using built-in defaults.` and defaults
are used for the run.

---

## 3. Exit code `3` — GUI unavailable (PySide6 missing)

**Symptom.** The log contains:

```
The graphical interface is unavailable (<import error>). Install the UI
dependency with 'pip install -e ".[dev]"' or run with --headless.
```

**Meaning.** `app.ui.shell` (which imports PySide6) could not be imported, so
the launcher refuses to crash and returns exit code `3`.

**Fixes**

```powershell
.\.venv\Scripts\python.exe -c "import PySide6; print(PySide6.__version__)"
pip install -e ".[dev]"        # installs PySide6 + matplotlib + dev tools
rogue-ap-hunter --headless     # works without a GUI at all
```

If the import still fails, check §5 (PySide6 install problems).

---

## 4. Database locked / permission errors, and where your data lives

**Symptoms**

- Exit code `1` with `Local storage could not be opened: cannot open database
  <path>: <sqlite error>`
- Log: `database transaction failed: …` / `query failed: …`
- `StorageError: database is locked`

**Where the data lives**

| Item | Default location | Override |
|------|------------------|----------|
| Data home | `%LOCALAPPDATA%\Rogue AP Hunter` | env `ROGUE_AP_HUNTER_HOME` |
| Database | `<home>\data\rogue_ap_hunter.sqlite3` | follows `--config` (then `<config dir>\data\…`) |
| Config | `<home>\config.json` | `--config PATH` |
| Log | `<home>\logs\rogue-ap-hunter.log` | — |

Relocate everything (portable mode / scratch space) before starting:

```powershell
$env:ROGUE_AP_HUNTER_HOME = "D:\RogueAPHunterData"   # current shell
rogue-ap-hunter
```

**Causes and fixes**

| Cause | Fix |
|-------|-----|
| A second instance is already running | Close the other window. The connection waits out short lock contention (10 s connect timeout, `PRAGMA busy_timeout = 5000`); a persistent lock means another instance still holds the file. |
| Read-only or permission-restricted home | Check NTFS permissions on the folder, or move the home with `ROGUE_AP_HUNTER_HOME`. |
| Home inside OneDrive/controlled-folder sync | Move it out of the synced folder — sync clients hold file locks that SQLite does not appreciate. |
| Antivirus/endpoint protection quarantining `.sqlite3` | Allow the folder (see §8). |
| Database file corrupted after an unclean shutdown | Stop the app, back up then delete `<home>\data\rogue_ap_hunter.sqlite3` — schema and data are recreated on next start (trusted profiles and history are lost; export CSV first if you need them). |
| Stale `-wal`/`-shm` files after a crash | Same as above: close all instances first; WAL recovers automatically on next clean open. |

Migrations run in a single transaction and are version-stamped, so an
interrupted upgrade leaves the old schema intact rather than half-migrated.

---

## 5. PySide6 installation problems

```powershell
python --version                 # must be 3.11 or newer (64-bit)
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
.\.venv\Scripts\python.exe -c "import PySide6, matplotlib; print('ok')"
```

| Problem | Fix |
|---------|-----|
| `No matching distribution found for PySide6` | Interpreter too old/new for an available wheel, or a 32-bit Python — use 64-bit CPython 3.11+. |
| `error: Microsoft Visual C++ …` while building | A package tried to build from source; upgrade pip first so binary wheels are used. |
| Install succeeds, import fails | You are likely running a different interpreter than the one you installed into: use `.\.venv\Scripts\python.exe -m app`, or re-activate the venv. |
| Corporate proxy blocks PyPI | Configure `pip` proxy/index settings, or install from a wheelhouse mirror. |
| `pip install -e ".[dev]"` reports only dev tools | Quote the extras exactly: `pip install -e ".[dev]"` (PowerShell needs the quotes). |

---

## 6. No desktop notification / toast not showing

**Behaviour to expect first:** toasts fire only for **new alerts** or
**severity escalations**, at **Suspicious or above**, at most **once per
minute per alert identity**. Low-severity alerts and repeated sightings
deliberately stay silent. The Alerts screen is always complete regardless.

**How to check whether a toast was attempted**

```powershell
Select-String -Path "$env:LOCALAPPDATA\Rogue AP Hunter\logs\rogue-ap-hunter.log" -Pattern "toast|ALERT"
```

| Log line | Meaning / fix |
|----------|---------------|
| `toast skipped: PowerShell not found` | PowerShell not on PATH — restore it (Windows Features / PATH), toasts then fall back to the log meanwhile. |
| `toast notification failed: …` / `toast returned <code>: …` | PowerShell ran but Windows refused the toast: check **Settings → System → Notifications** (make sure notifications and PowerShell are allowed) and **Focus assist / Do not disturb**. |
| `ALERT [severity] …` (WARNING) | The `LogNotifier` fallback fired — the alert *was* delivered to the log. |

Other things to verify:

- Notifications are only raised by the running application (they are not
  replayed from history).
- The toast uses the Windows PowerShell AUMID; if your organisation disables
  toast notifications for that app, only the log channel remains.
- The Settings checkbox *"Show Windows toast notifications"* is stored in
  `config.json` and reported at startup; in the current build the notifier
  chain (toast → log) is constructed once at launch and the checkbox does not
  switch it off mid-session (known limitation, see `docs/user-manual.md` §3.7).

---

## 7. The "Signal history" chart tab is missing (matplotlib)

The Investigation page imports matplotlib's Qt backend at start-up; if that
import fails, the **Signal history** tab is simply not added and a debug line
is logged: `matplotlib Qt backend unavailable; charts are disabled`. Everything
else on the page still works.

```powershell
.\.venv\Scripts\python.exe -c "from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg; print('ok')"
pip install -e ".[dev]"    # matplotlib>=3.8 is a declared runtime dependency
```

If the import works in a terminal but not in the packaged `.exe`, the bundle
is stale — rebuild with `.\scripts\build.ps1 -Clean`.

---

## 8. Antivirus blocking PyInstaller builds

**Symptoms:** `dist\RogueAPHunter\RogueAPHunter.exe` deleted, quarantined, or
crashes immediately; PyInstaller fails while writing `build/`/`dist/`; smart
screen warnings on the produced executable.

**Why:** unsigned one-folder/one-file executables built locally are a common
false-positive pattern for heuristic AV engines.

**What to do**

- Add exclusions for the repository's `build\` and `dist\` folders (and the
  PyInstaller work folder) **only on your own machine**, then rebuild:
  `.\scripts\build.ps1 -Clean`.
- Prefer the default **onedir** build (`dist\RogueAPHunter\`) — it is less
  likely to trip heuristics than `-OneFile`, and easier for AV to analyse.
- Use `-Console` while diagnosing: it keeps a console window so you can see
  startup errors instead of a silent exit.
- The build script already runs `ruff check .` and the full test suite before
  packaging, so a failure there is a code/test problem, not AV.
- Verify the produced binary yourself: `& '.\dist\RogueAPHunter\RogueAPHunter.exe' --version`.

`build.ps1` installs PyInstaller into the virtual environment on first use;
only free tools are involved. Full packaging steps, the
`rogue-ap-hunter.spec` file and verification:
[`packaging.md`](packaging.md).

---

## 9. Enabling DEBUG logging and finding the log files

**Enable DEBUG for one run** (works with or without the GUI):

```powershell
rogue-ap-hunter --headless --log-level DEBUG
python -m app --log-level DEBUG
```

Valid levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. The command-line
value overrides everything for that run. (The *Log level* field in Settings is
stored in `config.json` as `log_level`; the process level is set from the
`--log-level` flag at startup.)

**Log file location** — `app.core.paths.log_file()`:

```
%LOCALAPPDATA%\Rogue AP Hunter\logs\rogue-ap-hunter.log
```

- Format: `%(asctime)s %(levelname)-8s %(name)s: %(message)s`
  (`2026-01-01 12:00:00 INFO     app.main: Rogue AP Hunter 0.1.0 starting`).
- Rotation: 1 MB per file, **3 backups** (`rogue-ap-hunter.log.1` … `.3`),
  UTF-8.
- With `ROGUE_AP_HUNTER_HOME` set, the same relative path under that home.
- Console output goes to `stderr` as well.
- If the log directory cannot be created you get
  `File logging disabled, cannot open log directory …` — the app keeps running
  with console logging only.

Print the paths from Python if in doubt:

```powershell
.\.venv\Scripts\python.exe -c "from app.core import paths; print(paths.app_home()); print(paths.log_file()); print(paths.database_path())"
```

---

## 10. Configuration problems

| Symptom | Fix |
|---------|-----|
| Settings do not stick | The Settings page shows the exact file it writes; check the status bar after **Save settings** (`Settings saved to <path>`). |
| `Configuration could not be loaded … using built-in defaults` | Fix or delete `config.json` (invalid JSON / wrong types). Unknown keys are ignored with a warning, not an error. |
| `Invalid settings` dialog on save | Thresholds must satisfy `0 < Suspicious < High < Critical ≤ 100`, interval 5–3600 s, retention 1–3650 days, weights 0–100. |
| Want a known-good config | `rogue-ap-hunter --write-default-config --config <path>` writes defaults to a chosen file. |
| Exit code `2` immediately | Argument error — `rogue-ap-hunter --help`. |

---

## 11. Detection results look wrong

| Symptom | Explanation | Fix |
|---------|-------------|-----|
| No alerts at all on first run | By design: the new-access-point rule is suppressed until observation history exists, and rules that need a baseline stay quiet without trusted profiles | Create trusted profiles, then scan again |
| Everything flagged as duplicate SSID | Mesh/enterprise networks legitimately broadcast one name from several radios | Register **all** approved BSSIDs on the trusted profile |
| My own network flagged as unknown BSSID | Its radio was never added to the baseline | Edit the profile and add the BSSID(s) |
| Scores seem too sensitive/insensitive | Default weights are research parameters | Tune weights/thresholds in Settings — see `docs/detection-methodology.md` |
| Only the first scan shows data | The adapter or `WlanSvc` stopped working after startup | See §1 |

---

## 12. Still stuck?

1. Re-run with `--log-level DEBUG` and capture the log.
2. Note: OS version, `netsh wlan show interfaces` output, app version
   (`rogue-ap-hunter --version`), exit code, and the exact log excerpt.
3. Check the existing docs: [`setup.md`](setup.md),
   [`user-manual.md`](user-manual.md),
   [`troubleshooting.md`](troubleshooting.md) (this file),
   [`testing-report.md`](testing-report.md),
   [`../SECURITY.md`](../SECURITY.md).
4. File an issue (security-sensitive reports: follow `SECURITY.md` §9).
   Redact SSIDs/BSSIDs if your organisation considers them sensitive — logs
   and CSV exports contain network identifiers by design.
