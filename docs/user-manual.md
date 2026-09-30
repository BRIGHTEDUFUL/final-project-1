# Rogue AP Hunter — User Manual

A screen-by-screen guide to the desktop application: what each screen means,
how to read a risk score, how to work through alerts, and what the keyboard
shortcuts do.

> **Scope reminder.** Rogue AP Hunter is a passive, defensive tool. It reads
> the Windows Wi-Fi scan results, compares them against a baseline **you**
> approve, and explains every score. Use it only on networks and premises you
> own or are authorised to assess. An alert is an indicator to verify — never
> proof of an attack.

---

## 1. Starting the application

```powershell
rogue-ap-hunter          # console-script entry point
python -m app            # equivalent module entry point
```

Useful command-line flags (see `app/main.py`):

| Flag | Effect |
|------|--------|
| `--headless` | Initialise configuration and logging, then exit without opening a window (exit code `0`). |
| `--config PATH` | Use an explicit configuration file instead of the per-user default. |
| `--log-level DEBUG\|INFO\|WARNING\|ERROR\|CRITICAL` | Override the process log level for this run. |
| `--write-default-config` | Write the default configuration to the selected file and exit. |
| `--version` | Print the version and exit. |

Exit codes: `0` success · `1` runtime failure · `2` invalid arguments ·
`3` the graphical interface could not be started (e.g. PySide6 missing).

### Layout of the window

```
┌──────────┬──────────────────────────────────────────────┐
│ Sidebar  │  Page header (title + description)           │
│          │                                              │
│ Dashboard│                                              │
│ Live …   │  Page content (tables, forms, tabs)          │
│ …        │                                              │
│          ├──────────────────────────────────────────────┤
│ Start    │  Status bar · "N open alerts · N critical"   │
│ monitoring                                              │
└──────────┴──────────────────────────────────────────────┘
```

- **Sidebar** — navigation buttons for the eight screens, plus the monitoring
  controls at the bottom: **Start monitoring** / **Stop monitoring**,
  **Scan once**, and a one-line monitoring state label.
- **Status bar** — shows the result of the most recent scan, confirmation of
  actions (settings saved, export written, network trusted) and the open-alert
  indicator on the right. The indicator turns amber when any high alert is
  open and red when a critical alert is open.

---

## 2. Monitoring controls (sidebar)

| Control | Behaviour |
|---------|-----------|
| **Start monitoring** | Starts the background scan loop. The first scan runs immediately, then repeats every *scan interval* seconds (default **15 s**, configurable 5–3600 s in Settings). The button becomes **Stop monitoring** and the label reads "Monitoring is on". |
| **Stop monitoring** | Stops the loop and waits up to 10 seconds for the current scan to finish. Consecutive-scan persistence counters live in memory: they survive a stop/start within the same run, and reset when the application exits. |
| **Scan once** | Queues exactly one scan on a background thread — the window stays responsive — and shows the summary in the status bar, formatted as `<n> networks, <n> findings, <n> new alerts in <seconds>s`. The button is disabled until the report arrives; if a scan is already running (the monitoring loop or a previous press) the status bar says so instead of queueing a duplicate. Works whether or not monitoring is on. |
| State label | "Monitoring is off", "Monitoring is on", or "Monitoring is on · issue: …" when scans are failing. |

A failed scan never interrupts you: it is reported in the status bar
(`Scan failed: …`) and in the log, and monitoring keeps retrying on the next
interval.

Pages refresh automatically after every completed scan.

---

## 3. Screen reference

### 3.1 Dashboard (`Ctrl+1`)

*"Live overview of the radio environment and current risk posture."*

| Element | Meaning |
|---------|---------|
| **Networks in last scan** | Number of radio observations captured by the most recent scan (a SSID broadcast from several radios counts once per radio). `0` and "not yet scanned" before the first scan; "failed" if the last scan errored. |
| **Trusted networks** | How many profiles exist in your approved baseline. |
| **Open alerts** | Alerts in `active` status (not yet acknowledged or resolved). |
| **Critical alerts** | Open alerts in the Critical band; the card is tinted red when non-zero. |
| **Current environment** | Your adapter's own connection as reported by `netsh wlan show interfaces`: interface name, connected SSID, access point (BSSID), channel, security, signal %, plus the time of the last scan and how many BSSIDs are in recorded history. Each value shows `—` until available. |
| **Most recent alerts** | The 8 newest active alerts: severity (colour-coded), score, type, SSID, BSSID, evidence (truncated), status, first-seen time. |
| Hint line | Points you to **Investigation** for the full reasoning behind any score. |

### 3.2 Live networks (`Ctrl+2`)

*"One row per radio currently known to the last scan."*

A table built from the most recent observations (up to 1,000), merged with
your trusted profiles and the latest stored risk score:

| Column | Meaning |
|--------|---------|
| SSID / BSSID | Network name and radio identifier. Hidden networks show an empty SSID. |
| Signal % | Signal quality as reported by Windows (0–100). |
| Security | Security label exactly as reported (e.g. `WPA2-Personal`). |
| Channel | Radio channel. |
| Trust | `Trusted` (profile exists and this radio is approved) · `Trusted name, new radio` (profile exists, this BSSID is not approved) · `Unknown` (no profile for this name). |
| Risk | Latest stored risk score for this identity, or empty if never scored. |
| Severity | Latest severity band, colour-coded. |
| Last seen | Time of the newest observation (`HH:MM:SS`). |

**Toolbar:** free-text filter over SSID/BSSID, a preset filter
(**All networks** / **Unknown only** / **Flagged only** / **Trusted only**,
where *Flagged* means severity above Low), a **Refresh** button, and the row
count. Click a column header to sort. **Double-click a row** to open
Investigation for that identity.

### 3.3 Investigation (`Ctrl+3`)

*"Evidence, history and reasoning for one network identity."*

Reached by double-clicking a row on Live networks, Alerts or History, or from
the Dashboard's hint. Shows one `(SSID, BSSID)` identity at a time.

- **Header** — identity title, latest score with severity colour, a severity
  badge, and **Add to trusted networks** (opens the trusted-network dialog
  pre-filled with the current SSID; enabled only when an SSID is known).
- **Current facts** — signal, security, channel, first seen, last seen, total
  alert occurrences, trust status (`Not in the trusted baseline`,
  `Trusted (approved radio)`, `Trusted name — radio not approved`, or
  `Trusted name (no BSSIDs registered yet)`) and the approved-BSSID baseline.
- **Tabs:**
  - **Reasons** — the latest score with its timestamp and one bullet per
    contributing rule, plus alert evidence for this identity. This is the
    authoritative "why 65 and not 30?" answer.
  - **Security observations** — distinct security labels seen over time,
    newest first.
  - **BSSID history** — for an SSID: every radio seen for it with counts and
    last-seen time; for a BSSID: every name that radio has broadcast.
  - **Alert history** — alerts for this identity with severity, type, score,
    status, occurrence count and evidence.
  - **Signal history** — matplotlib chart of signal % over time. This tab
    appears only when the matplotlib Qt backend is available (see
    `docs/troubleshooting.md` if it is missing).

### 3.4 Alerts (`Ctrl+4`)

*"Risk-scored, explainable events. Acknowledge or resolve after review."*

The working queue. Columns: Severity, Score, Type, SSID, BSSID, Status, Seen
(occurrence count), First seen, Last seen, Evidence (truncated — the panel
below the table shows the full text for the selected alert).

**Filters:** status (**Active** / **Acknowledged** / **Resolved** /
**All statuses**) and severity (**All severities** / Critical / High /
Suspicious / Low). The list holds up to 1,000 matching rows and refreshes
after every scan.

#### Acknowledging and resolving

1. Select a row (single click).
2. Press one of:
   - **Acknowledge** — "I have seen this and am investigating."
   - **Resolve** — "Reviewed and closed."
   - **Reopen** — return it to the active list.
3. The row updates immediately; a confirmation or error appears in a dialog
   if no row was selected or the update failed.

Status meanings:

| Status | Counts as open? | Effect |
|--------|-----------------|--------|
| `active` | Yes | Shown in Dashboard counts and the status-bar indicator; matches future occurrences of the same alert (deduplication). |
| `acknowledged` | No | Still stored and filterable; excluded from open counts. |
| `resolved` | No | Closed; a *new* condition of the same type can create a fresh alert. Pruned after the retention window. |

Recurring sightings of the same open alert (same type + same SSID + same
BSSID) do **not** create duplicates: the existing row's **Seen** count
increments, `Last seen` advances and new reasons are merged in. If the score
rises, the stored score/severity are updated — and if the severity band went
**up**, that counts as an escalation and can trigger a desktop notification.

**Export CSV…** writes the alerts matching the current filters (up to 100,000
rows) to a file you choose (default name `rogue_ap_hunter_alerts.csv`).
Columns: `id, created_at, first_seen, last_seen, status, severity, risk_score,
alert_type, ssid, bssid, occurrence_count, reasons`. The file is UTF-8 with
BOM (opens correctly in Excel) and written atomically.

**Double-click** a row to open it in Investigation.

### 3.5 Trusted networks

*"Approval baseline: detection rules compare observations against these
profiles."*

This is the single most important screen for detection quality: without a
baseline, only structural indicators (duplicate names, unusual signal) can
fire.

- **Table:** SSID, Approved BSSIDs, Expected security, Created, Notes.
- **Add network / Edit** open a dialog with:
  - **SSID** — exact network name (required, non-blank).
  - **Approved BSSIDs** — one `aa:bb:cc:dd:ee:ff` per line; **leave empty** if
    you only know the name (the profile then approves no radio, and the
    "unknown BSSID" rule stays dormant for it).
  - **Expected security** — `(not specified)`, `Open`, `WEP`, `WPA`,
    `WPA2-Personal`, `WPA3-SAE`, `WPA2-Enterprise`, `WPA3-Enterprise`. When set,
    weaker observations trigger the security-downgrade rule. `(not specified)`
    disables that rule for the profile.
  - **Notes** — free text for operators.
  - Invalid BSSIDs are rejected in the dialog with an inline error.
- **Remove** asks for confirmation and warns that future observations of that
  name will be treated as unknown.
- Saving refreshes every other screen.

**Tip shown on the page:** mesh and enterprise networks legitimately broadcast
one name from several radios — register *all* approved BSSIDs so they do not
flag as duplicate SSID or unknown BSSID.

### 3.6 History

*"Stored sessions and observations (retention window applies)."*

- **Scan sessions** (last 100): ID, Started, Completed, Status
  (`running`/`completed`/`failed`), Networks count.
- **Stored observations** (last 500 shown; counter shows the full total):
  Observed, SSID, BSSID, Signal %, Security, Channel. Double-click a row to
  investigate that identity.
- **Export observations CSV…** exports up to 100,000 stored observations
  (default name `rogue_ap_hunter_observations.csv`; columns
  `id, observed_at, ssid, bssid, signal_strength, security, channel`).

Data older than the **data retention** setting (default 90 days) is pruned
automatically about every 20 scans. Pruning removes old observations, old
score history and *closed* alerts; active alerts are kept.

### 3.7 Settings

*"Local configuration only — nothing here is sent anywhere."* The file path
being edited is shown at the bottom of the page.

| Group | Setting | Range / notes |
|-------|---------|---------------|
| Monitoring | Scan interval | 5–3600 seconds (default 15). If changed while monitoring runs, the loop restarts with the new interval. |
| Monitoring | Data retention | 1–3650 days (default 90). |
| Monitoring | Log level | Stored level for the configuration (`DEBUG`…`CRITICAL`). The *process* log level for a run is set by the `--log-level` flag at startup. |
| Severity thresholds | Suspicious ≥, High ≥, Critical ≥ | 1–100 each; must satisfy `0 < suspicious < high < critical ≤ 100` (defaults 30 / 60 / 80). "Low" is anything below the Suspicious threshold. |
| Risk weights | Duplicate SSID, Unknown BSSID, Security downgrade, New access point, Suspicious signal, Persistence | 0–100 each, step 5 (defaults 25 / 20 / 30 / 10 / 5 / 10). Each distinct rule contributes its weight **once** per identity, clamped to a 0–100 total. |
| Notifications | "Show Windows toast notifications for new alerts" | Stored as `notifications_enabled` in `config.json`. See the note below. |
| Passive frame observer | "Analyze beacon frames for extra evidence (requires the Npcap driver)" | Stored as `frame_observer_enabled` (default on). Status line shows `running — N BSSIDs observed in beacons`, `unavailable — …` (driver missing), `error — …` (adapter refused) or `disabled`. See the note below. |

**Save settings** validates first (an invalid combination such as
Suspicious ≥ High shows a warning and changes nothing), then writes the file
atomically and applies it to the running services. **Reload** discards
unsaved edits.

> **About the frame observer:** it reads only broadcast beacon and
> probe-response frames — SSID, channel, capability and information
> elements — through the system Npcap driver (install the free driver from
> npcap.com if you want it; without it the app is netsh-only and the status
> line says so). Facts it can attach to alerts: *WPS advertised*,
> *802.11w management frame protection not in use/optional*, *hidden SSID*,
> *legacy WPA1 or WEP-era security*, *SAE (WPA3) advertised* (capped at four
> lines per alert). It never transmits, never decrypts, never records client
> device addresses, and **never changes a risk score** — evidence lines are
> purely additional context. Toggling the checkbox starts or stops capture
> immediately, without restarting the application.

> **Honest note on the notifications checkbox:** the flag is validated, stored
> and reported at startup, but in the current build the notifier chain
> (Windows toast → log) is constructed once when the application starts and
> the checkbox does not switch it off mid-session. Toasts only fire for new
> alerts or severity escalations at Suspicious or above, with a one-minute
> cooldown per alert — the in-app Alerts list is always complete regardless.

### 3.8 About

Version, licence (MIT), the "what it does not do" list, how to read alerts,
the authorisation notice, the data directory path, the configuration path, and
a pointer to `THIRD_PARTY_LICENSES.md`.

---

## 4. How to read risk scores and severities

Every score is a transparent sum of the rules that fired for one identity:

```
score = Σ (largest weight of each distinct rule that fired)   clamped to 0–100
```

Default weights (`Config.risk_weights`, editable in Settings):

| Rule | Default weight | Fires when… |
|------|---------------:|-------------|
| Duplicate SSID | 25 | One SSID is broadcast by ≥2 radios and this radio is not approved for it. |
| Unknown BSSID | 20 | A trusted profile with registered BSSIDs is seen from a radio that is not in its approved set. |
| Security downgrade | 30 | Observed security is weaker than the profile's expected security. |
| New access point | 10 | A radio appears that is not in the recorded history (suppressed on the very first scan). |
| Suspicious signal | 5 | An unapproved radio out-signals your own connection, or reports ≥95% signal with no prior history. |
| Persistence | 10 | The same identity produced findings in 3+ consecutive scans. |

Severity bands (defaults; thresholds configurable):

| Band | Score | Colour |
|------|-------|--------|
| Low | 0–29 | green |
| Suspicious | 30–59 | amber |
| High | 60–79 | orange |
| Critical | 80–100 | red |

Worked example: a trusted network seen from an unapproved radio that also
shares its SSID scores `20 (unknown BSSID) + 25 (duplicate SSID) = 45` →
**Suspicious**. The same radio seen in three consecutive scans adds
`+10 (persistence) = 55`, still Suspicious; if its security also downgrades,
`+30 = 85` → **Critical**.

Where to look: **Investigation → Reasons** lists every contributing rule with
its explanation, and the Alerts detail panel shows the same evidence text.

Full methodology, including false-positive discussion:
[`docs/detection-methodology.md`](detection-methodology.md).

---

## 5. Notifications

- Delivered as a native Windows toast raised through the built-in PowerShell
  runtime (no third-party SDK, no cloud).
- **When:** a brand-new alert is created, or an existing open alert escalates
  to a higher severity band — and only for alerts at **Suspicious** or above.
- **Cooldown:** at most one toast per alert identity
  (SSID + BSSID + type) per **60 seconds**.
- **Fallback:** if the toast cannot be shown (PowerShell missing, blocked by
  Windows settings), the notification is written to the application log at
  `WARNING` level, and the in-app Alerts list is always authoritative.
- Suppressing toasts never suppresses the Alerts screen or storage.

---

## 6. Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` | Go to Dashboard |
| `Ctrl+2` | Go to Live networks |
| `Ctrl+3` | Go to Investigation |
| `Ctrl+4` | Go to Alerts |
| `F5` | Refresh the current page |

Other interaction shortcuts come from Qt itself: click column headers to
sort, double-click table rows to investigate, `Tab` to move between controls,
`Esc` to close dialogs.

---

## 7. A suggested workflow

1. **Establish a baseline.** Open *Trusted networks* and add your own
   network(s): SSID, every approved BSSID (`netsh wlan show networks
   mode=bssid` lists them), and expected security.
2. **Scan once** to confirm the environment parses and your network shows as
   *Trusted*.
3. **Start monitoring** and leave it running during a working day.
4. **Triage alerts** as they appear: read the evidence, check *Investigation*,
   then **Acknowledge** what you verified as legitimate (guest AP, mesh node)
   and **Resolve** what you have closed.
5. **Export CSV** for your records or ticket system when needed.
6. **Tune thresholds and weights** in Settings only after you understand why
   the current values fire; keep weights explainable rather than zeroing rules
   to silence them.

---

## 8. Where your data lives

Default home directory: `%LOCALAPPDATA%\Rogue AP Hunter\`

```
config.json                      settings, thresholds, risk weights
logs\rogue-ap-hunter.log         rotating log (1 MB × 3 backups)
data\rogue_ap_hunter.sqlite3     observations, sessions, alerts, profiles, scores
```

Set the `ROGUE_AP_HUNTER_HOME` environment variable to relocate all of it
(portable mode). CSV exports go wherever you choose in the save dialog.
Nothing is transmitted off the machine.
