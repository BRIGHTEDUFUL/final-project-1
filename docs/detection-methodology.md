# Rogue AP Hunter — Detection Methodology

How Rogue AP Hunter decides that something is worth your attention: the six
rules, their configurable weights, how a score and severity are produced, how
alerts are deduplicated, where the false positives come from — and the
statement that matters most:

> **An alert is an indicator to verify, never proof of malicious activity.**
> Nothing in this tool establishes intent, authorship or an attack. It reports
> observable patterns in scan metadata so that a human can check them.

Source of truth for everything below:
`app/detection/rules.py`, `app/detection/engine.py`, `app/scoring/risk.py`,
`app/core/config.py` (`RiskWeights`), `app/models/alert.py` (`Severity`).

---

## 1. Inputs to detection

Each scan produces a `DetectionContext` (`app/detection/findings.py`):

| Field | Meaning |
|-------|---------|
| `observations` | Every radio seen in this scan (SSID, BSSID, signal %, security, channel, timestamp). |
| `trusted` | Your approved baseline (`TrustedNetwork` profiles). |
| `known_bssids` | Every BSSID recorded in previous scans (loaded from SQLite). |
| `connected_bssid` / `connected_signal` | The state of your own adapter's connection, used for signal comparison. |
| `history_available` | `False` on the first scan of a fresh database — see §3. |

Identity is the pair **`(SSID, BSSID)`** — every rule, score, alert and
deduplication key is scoped to it.

---

## 2. The six rules

Rules are **pure functions** from a context to findings. Each finding carries
a `weight`, a human-readable `explanation`, and an `evidence` dictionary with
the data needed to verify it. Weights are configuration values
(`Config.risk_weights`) and can be tuned per installation in Settings.

| # | Rule (`FindingRule`) | Default weight | Fires when |
|---|----------------------|---------------:|------------|
| 1 | `duplicate_ssid` | **+25** | One SSID is broadcast by **two or more distinct BSSIDs** and *this* radio is not in the profile's approved set (or no profile exists for the name). Each unapproved radio gets its own finding. |
| 2 | `unknown_bssid` | **+20** | A trusted profile **with registered BSSIDs** is seen from a radio that is not in its approved list. Disabled when the profile has no BSSIDs (`knows_bssids` is false). |
| 3 | `security_downgrade` | **+30** | A trusted profile specifies an expected security mode and the observed mode is **provably weaker** (ordering: Open < WEP < WPA < WPA2 < WPA3). Unknown/unreported security never triggers it. |
| 4 | `new_access_point` | **+10** | A BSSID appears that is **not in the recorded history** (`known_bssids`). Suppressed entirely when there is no history — see §3. |
| 5 | `suspicious_signal` | **+5** | An **unapproved** radio either (a) reports a stronger signal than your own connected network, or (b) reports signal ≥ **95 %** (`SUSPICIOUS_SIGNAL_THRESHOLD`) while having no prior history. Approved radios are never flagged. |
| 6 | `persistence` | **+10** | The **same identity** produced at least one finding in **3 consecutive scans** (`persistence_scans`, default 3, minimum 2). Tracked in memory by `DetectionEngine`. |

Notes on individual rules:

- **Duplicate SSID is contextual, not absolute.** The finding text explicitly
  says when other radios are in the trusted profile, and its `evidence`
  carries the note *"Multiple access points can legitimately share an SSID
  (mesh/enterprise); verify before acting."*
- **Unknown BSSID needs a baseline.** A name you have never registered cannot
  trigger it — that is what the new-access-point rule is for.
- **Suspicious signal has two independent heuristics** (out-signalling your
  connection; near-maximum signal from an unknown radio), both restricted to
  radios that are neither connected nor approved.
- **Persistence is the only stateful rule**: counters live in
  `DetectionEngine._consecutive` and are cleared for any identity that stops
  producing findings (and when the process exits).

---

## 3. First-scan history suppression

On the very first scan after installation (or after the observation history is
empty), `history_available` is `False`, so the **new-access-point rule returns
no findings**. Without this, every radio in the environment would be "new" and
the tool would flag the entire building on first run.

Consequences:

- First scan: only structural rules can fire (duplicate SSID, unknown BSSID,
  security downgrade, suspicious signal).
- From the second scan on: every BSSID stored by the first scan counts as
  known, so `new_access_point` fires only for genuinely unseen radios.
- Resetting the database (deleting the SQLite file) restores the "quiet first
  scan" behaviour.

This is covered by
`tests/unit/test_detection_rules.py::test_first_scan_without_history_suppresses_the_rule`
and `tests/integration/test_monitoring.py::test_first_scan_records_everything`.

---

## 4. Scoring: sum, clamp, explain

```
score(identity) = clamp( 0, 100,  Σ over distinct rules  max(weight of that rule's findings) )
```

- Each **distinct rule contributes its configured weight exactly once** per
  identity — if the duplicate-SSID rule fires for three radios of the same
  identity, the largest of those contributions counts, not the sum.
- Findings with weight `0` contribute nothing.
- The total is clamped to `0..100`.

**Every point is traceable.** `RiskScorer.assess()` keeps, per rule, the
highest-weight finding and turns its explanation into a reason string
(`"duplicate_ssid: SSID 'Corp' is broadcast by 3 different access points; …"`),
plus a `rule_scores` breakdown `[(rule, points), …]`. The same text appears in
the alert evidence, the Alerts detail panel and Investigation → Reasons.

Worked example with defaults:

| Fired rules | Calculation | Score | Severity |
|-------------|------------|------:|----------|
| unknown BSSID | 20 | 20 | Low |
| unknown BSSID + duplicate SSID | 20 + 25 | 45 | Suspicious |
| + persistence | 20 + 25 + 10 | 55 | Suspicious |
| + security downgrade | 20 + 25 + 10 + 30 | 85 | Critical |
| all six rules | 25+20+30+10+5+10 | 100 | Critical |

(Clamping matters when weights are raised above their defaults in Settings —
for example six rules at weight 60 each would total 360 and report 100.)

---

## 5. Severity bands

`Severity.from_score(score, thresholds)` maps the clamped score using the
configured thresholds (`0 < suspicious < high < critical ≤ 100`):

| Band | Default range | Colour in UI |
|------|---------------|--------------|
| `low` | 0 – 29 | green `#3fae6b` |
| `suspicious` | 30 – 59 | amber `#e0a63a` |
| `high` | 60 – 79 | orange `#e07a3f` |
| `critical` | 80 – 100 | red `#e04f4f` |

The thresholds themselves are editable in Settings
(`suspicious_threshold`, `high_threshold`, `critical_threshold`); validation
keeps them strictly ascending. Out-of-range scores are clamped before mapping,
so an extreme value can never produce an unknown band.

---

## 6. Persistence across scans

- `DetectionEngine` keeps `identity → consecutive_scans_with_findings`.
- After each evaluation, counters for identities that produced **no** findings
  are deleted (the streak ends).
- When a counter reaches `persistence_scans` (default **3**), an extra
  `persistence` finding (+10) is appended for that scan, with evidence
  `{"consecutive_scans": n, "threshold": 3}`.
- The counter keeps growing afterwards (the finding text reports the current
  count), but the weight still contributes only once to the score.
- State is in-memory: it survives stopping and starting monitoring within a
  run, and resets when the application exits.

---

## 7. Alerts: deduplication, occurrences, escalation

After scoring, each identity with a score > 0 becomes an `Alert` whose
`alert_type` is the **dominant rule** (highest-weight finding; ties broken by
rule name), and is handed to `AlertManager.record()`.

**Deduplication key** (`AlertRepository.find_open_match`):

```
alert_type  +  status = 'active'  +  SSID  +  BSSID
```

(NULL SSID/BSSID values compare equal to empty strings, so hidden networks
deduplicate correctly.)

| Situation | Result |
|-----------|--------|
| No open match | New row inserted (`created = true`). First notification opportunity. |
| Open match exists | **No new row.** `occurrence_count += 1`, `last_seen` advances, new reason strings are merged in (deduplicated), `first_seen` preserved. |
| Score rose above the stored one | Stored `risk_score` and `severity` are updated to the new values. |
| Severity band went **up** | `escalated = true` → second notification opportunity. |
| Same identity but a different `alert_type` | Separate alert (different key). |
| Previous alert was acknowledged/resolved | It is no longer `active`, so a fresh alert can be created. |

**Notification policy** (`AlertManager._maybe_notify`):

- Fires only on meaningful transitions: **created** or **escalated**.
- Only at severity **Suspicious or above** (`notify_below_severity`).
- At most once per `(ssid, bssid, alert_type)` every **60 seconds**
  (`DEFAULT_MIN_NOTIFICATION_INTERVAL_SECONDS`).
- Delivered by the notifier chain (Windows toast → log); a failing notifier is
  logged and never breaks monitoring.

**Workflow states:** `active → acknowledged | resolved`, reversible with
*Reopen*. Only `active` alerts count toward the Dashboard/status-bar open
counts. Closed alerts older than the retention window are pruned; active ones
are kept.

---

## 8. False positives: what else looks like this

The rules deliberately favour sensitivity with explainability. Expect these
common, legitimate explanations:

| Observation | Likely benign cause | What to do |
|-------------|--------------------|------------|
| Duplicate SSID with several BSSIDs | **Mesh systems and enterprise networks** broadcast one name from many radios (APs, extenders, band steering 2.4/5/6 GHz). | Register every approved BSSID in the trusted profile; the rule then ignores them. |
| Unknown BSSID on a trusted name | New/renamed/replaced hardware, a guest network reusing your name, or a mesh node added since you created the baseline. | Verify the radio's identity (BSSID, location, channel), then add it to the profile — or treat as a real finding. |
| Security downgrade | APs advertising mixed modes (`WPA2/WPA3-Personal`) can be reported as the weaker mode by some drivers; captive-guest APs may legitimately be Open. | Check the actual AP configuration; set the profile's expected security to match reality, or `(not specified)` to disable the rule. |
| New access point | Neighbours, visitors, printers, IoT devices, phones in hotspot mode — anything the environment has not recorded before. | This is a +10 lead only; confirm with signal/channel before reacting. |
| Suspicious signal | **Low-end/malformed signal data**, an AP in the next room with clear line of sight, or your own adapter's signal readings being noisy (USB adapters, drivers). | Weigh it as +5 — the weakest indicator — and corroborate with other rules. |
| Hidden SSIDs | Hidden networks still report BSSIDs but may report no SSID. The duplicate-SSID rule skips SSID-less entries entirely, and each hidden radio is its own `(SSID, BSSID)` identity. | Investigate by BSSID; note that visibility is inherently limited. |
| Persistence | A transient condition (e.g. a temporarily visible rogue-looking radio, or a scan taken while an AP reboots) still needs 3 consecutive scans to score +10. | Persistence is designed to separate one-off noise from sustained conditions. |
| Nothing flagged at all | Passive scanning only sees what the local adapter reports at scan time; a rogue AP can be between scans or on a band your adapter does not scan. | This tool complements, and does not replace, proper WIPS/IDS coverage. |

**Design choices that reduce noise:**

- First-scan suppression of the new-AP rule (§3).
- One contribution per distinct rule in scoring (§4) — repeated sightings of
  the same problem cannot inflate a score.
- Alert deduplication (§7) — the queue shows conditions, not scan events.
- Everything requires **your baseline** to become specific: without trusted
  profiles, only structural rules fire, so an unconfigured install stays quiet
  instead of crying wolf.

---

## 9. Limitations (read before acting)

- Heuristic metadata analysis only: no packet capture, no handshake
  inspection, no cryptographic verification of an access point, no
  deauth/jamming detection, no client-side telemetry.
- Detection quality is bounded by what `netsh` reports for your adapter and
  driver (scan cadence, bands, hidden-network handling).
- A low score does not prove a network is safe; a high score does not prove it
  is hostile.
- **Act only against equipment you own or are authorised to assess**, and only
  after verifying an alert by other means (physical location, configuration,
  authorised packet analysis outside this tool).

See [`../SECURITY.md`](../SECURITY.md) for the defensive-scope statement and
responsible-use policy, and [`user-manual.md`](user-manual.md) for how this
maps onto the screens.
