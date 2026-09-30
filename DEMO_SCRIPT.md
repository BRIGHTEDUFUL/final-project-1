# Rogue AP Hunter — Demonstration Script

**Scope statement:** this demonstration uses only equipment you own or have
explicit written permission to assess (for example your own access point and
your own hotspot). No production network, neighbour, guest, or third party may
be used. Nothing in this script transmits anything other than normal Wi-Fi
association traffic from the lab devices themselves — the application only
*observes*.

**Total time:** ~15 minutes (plus ~10 minutes of lab setup).

---

## 0. Setup (before the audience arrives)

1. **Lab gear (owned/authorised only)**
   - Access point A: your normal network, SSID `LabNet`, WPA2/WPA3-Personal.
   - Device B: a second owned radio (phone hotspot or travel router) that can
     broadcast the *same* SSID `LabNet` with weaker/no security. This is the
     controlled anomaly.
   - The demo PC: Windows 10/11 with a working Wi-Fi adapter.
2. **Fresh state (optional but recommended)**

   ```powershell
   # stop the app first, then wipe previous demo data
   Remove-Item "$env:LOCALAPPDATA\Rogue AP Hunter" -Recurse -Force
   ```

3. **Launch**

   ```powershell
   .\dist\RogueAPHunter\RogueAPHunter.exe     # packaged build
   # or from source:
   .\.venv\Scripts\python.exe -m app
   ```

4. Confirm on **Dashboard** that *Last scan* says `not yet scanned` and
   *BSSIDs in history* is `0` (fresh install) — this proves first-scan
   behaviour honestly.

---

## 1. Normal, trusted baseline (≈3 min)

**Goal:** show that a known-good environment produces no alarm.

1. Open **Trusted networks → Add network**.
   - SSID: `LabNet`
   - Approved BSSIDs: the real BSSID of access point A (read it from
     *Live networks* after the first scan, or from the router's label)
   - Expected security: `WPA2-Personal` (or whatever A actually uses)
   - Notes: `demo baseline`
   - **Save.** The profile appears in the table.
2. Press **Scan once** (or **Start monitoring**).
3. Show **Dashboard**:
   - environment card lists the connected SSID, BSSID, channel, security;
   - *Open alerts* is `0`, or alerts exist only from the pre-baseline scan.
4. Show **Live networks**: the `LabNet` row reads **Trusted** (and
   *Trusted name, new radio* would appear if a second radio were present but
   not yet approved).
5. Point at **About** → "What it does not do" to frame the ethics first.

> **Talking point:** the baseline is *your* approval list. The tool has no
> cloud reputation feed and makes no claim about who owns a radio — it only
> compares against what you registered.

---

## 2. Controlled anomaly — duplicate identity (≈4 min)

**Goal:** produce a reproducible, explainable finding.

1. Enable the second owned radio: hotspot named `LabNet` (device B).
2. Press **Scan once** while watching **Live networks**.
3. Expected outcome (default weights, see `docs/detection-methodology.md`):

   | Indicator | Weight | Why it fires |
   | --- | --- | --- |
   | Duplicate SSID | +25 | two radios broadcast `LabNet`, only A is approved |
   | Unknown BSSID | +20 | device B's radio is not in `approved_bssids` |
   | Suspicious signal (situational) | +5 | B out-signals or closely shadows your connection |

   → typically **45–50 → Suspicious** (thresholds 30/60/80 are configurable).
4. If the hotspot is set to an open/weak security while the baseline expects
   WPA2-Personal, the **security downgrade** rule adds **+30 → High/Critical**
   on the next scan. Use this variant only if your lab permits it.
5. Point out the new row in **Alerts**: severity badge, score, evidence text.

> **Talking point (never skip):** an alert is *a pattern worth verifying*,
> not proof of an attack. A guest AP configured with the same name, a mesh
> node, or a neighbour reusing a default SSID all look similar. The correct
> next step is physical/administrative verification of *your* equipment.

---

## 3. Risk calculation and explainability (≈3 min)

**Goal:** prove the score is auditable, not a black box.

1. Double-click the `LabNet` row in **Live networks** (or the alert in
   **Alerts**) → **Investigation** opens.
2. Walk the screen top to bottom:
   - header: identity, current **score**, severity badge;
   - **Current facts**: signal, security, channel, first/last seen, alert
     occurrences, trust status, baseline (approved BSSIDs);
   - **Reasons** tab: each contributing rule in plain language;
   - **Signal history** tab: the Matplotlib chart of recorded signal over time;
   - **BSSID history** tab: every radio seen for this name, with counts;
   - **Alert history** tab: status transitions and occurrence counts.
3. Open **Settings** briefly to show that every weight and threshold is
   visible and editable (weights 25/20/30/10/5/10, bands 30/60/80), then
   **Save settings** — and mention that changes apply to the next scan
   without restarting.

---

## 4. Alert lifecycle and notification (≈2 min)

1. Stay on **Alerts**. Select the alert.
2. Press **Acknowledge** → status changes, occurrence counter intact.
3. Press **Resolve** → the alert leaves the *Active* filter but remains in
   *All statuses* — nothing is ever deleted.
4. Mention notifications: a Windows toast fires **only** on a new alert or a
   severity escalation, with a 60-second cooldown per alert identity; the
   in-app list is always complete.
5. Press **Export CSV…** and open the file in a spreadsheet: columns
   `id, created_at, first_seen, last_seen, status, severity, risk_score,
   alert_type, ssid, bssid, occurrence_count, reasons`.

---

## 5. History and recovery (≈2 min)

1. **History** page: session list (started/completed/status/network count)
   plus the stored observation timeline; double-click a row to investigate.
2. **Export observations CSV…** for an offline record.
3. Optional durability proof: close the app, relaunch, return to **History** —
   the same sessions, alerts and BSSID history are present (SQLite, local
   file `%LOCALAPPDATA%\Rogue AP Hunter\data\rogue_ap_hunter.sqlite3`).
4. Resolve the demo alert, then show **Dashboard** returning to `0` open
   alerts while **History** still shows it — investigation record survives
   resolution.

---

## 6. Close (≈1 min)

- Recap: passive observation only (`netsh wlan show …`), offline-first, no
  credentials, no injection, no auto-connect, MIT-licensed, all data local.
- Show `docs/detection-methodology.md` (false-positive discussion) and
  `SECURITY.md` (security/privacy review).
- Disable device B's hotspot and, if you modified access point A during the
  demo, restore its original configuration.

---

## Fallback: fully offline demonstration

If no radio may be transmitted (airplane demos, restricted rooms), the same
flow runs against recorded output:

```powershell
# run the test suite: it drives the whole pipeline on captured fixtures
.\.venv\Scripts\pytest.exe tests\integration -v
# or run the benchmark to show real processing times
.\.venv\Scripts\python.exe scripts\benchmark.py
```

`tests/fixtures/netsh_show_networks_multi.txt` is sanitized real `netsh`
output; the integration tests demonstrate detection, scoring, alerting,
persistence and lifecycle exactly as the GUI would.
