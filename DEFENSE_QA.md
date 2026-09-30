# Defense Q&A — Anticipated Questions About Rogue AP Hunter

Prepared answers for reviewers, instructors, defenders and critics. Every
answer reflects what the code actually does; if an answer cannot be supported
by the implementation, the question is a finding, not a talking point.

---

## Scope and legitimacy

**Q: Is this an offensive tool?**
No. It performs read-only observations through Windows' own
`netsh wlan show networks` / `netsh wlan show interfaces` commands. It cannot
inject frames, deauthenticate clients, jam, crack, capture credentials, or
connect to any network. There is no code path that writes to wireless
settings. See `SECURITY.md` for the code-level review.

**Q: What authorisation does a user need?**
Assessing a wireless network without permission can be illegal. The tool is
intended for networks and premises you own or are explicitly authorised to
assess (your home/office AP inventory, a customer under contract, a lab). The
About screen, README and demo script all repeat this limit. The application
itself cannot verify authorisation — that responsibility stays with the
operator.

**Q: Does it collect personal data?**
It records what any Wi-Fi client already sees: broadcast SSIDs, BSSIDs,
signal strength, channel and security mode — data your adapter exposes to
every nearby device by design. Nothing is transmitted off the machine: there
is no network code beyond local `netsh` execution, no telemetry, no analytics,
no paid API.

**Q: Where is the data stored?**
In `%LOCALAPPDATA%\Rogue AP Hunter\` (config JSON, rotating log, SQLite
database), overridable with the `ROGUE_AP_HUNTER_HOME` environment variable.
Deleting that folder removes everything.

---

## Detection and scoring

**Q: How is the score computed — is it a black box?**
No. Each of the six rules contributes its configured weight **once per
identity**; contributions are summed and clamped to 0–100, then mapped to
Low/Suspicious/High/Critical at 30/60/80. The Investigation screen lists the
exact reasons for the current score, and every score row persists its reason
list in SQLite. See `docs/detection-methodology.md`.

**Q: Why should anyone trust a score?**
They shouldn't "trust" it — they should be able to *reproduce* it. Weights and
thresholds are visible and editable in Settings, defaults are documented in
the master documentation §10, and tests assert the arithmetic
(`test_score_counts_each_rule_once`, `test_score_is_clamped_to_100`,
`test_full_assessment_explains_every_point`).

**Q: How do you avoid crying wolf? (False positives)**
Known failure modes and their mitigations:

| False positive | Mitigation |
| --- | --- |
| Mesh/enterprise multi-radio networks | register every radio in `approved_bssids`; the duplicate-SSID and unknown-BSSID rules then stay quiet |
| First sight of any AP | the new-access-point rule is suppressed on the very first scan (no history yet) |
| Transient disappearances | persistence requires consecutive scans before firing |
| Hidden SSIDs | duplicate detection ignores nameless identities |
| Low/absent signal environmental noise | the signal rule requires a measured signal and a BSSID |
| Weights don't fit a site | every weight and threshold is configurable; zero disables a rule |

Known residual risk: this is a *heuristic* tool. Novel topologies (for
example a rogue radio inside an approved BSSID list) are out of scope for a
passive observer.

**Q: Is an alert proof of an evil twin?**
Never. An alert means *a pattern that warrants verification*. The product
language (UI, docs, notifications) deliberately avoids attributing intent or
malice; the correct response is administrative verification of your own
equipment, not confrontation or automated countermeasures.

**Q: What happens when the environment is legitimately changed?**
Register the new radio under **Trusted networks** (Investigation → *Add to
trusted networks* prefills the name), or edit the baseline. Alerts raised
earlier can be acknowledged/resolved and remain in history.

---

## Reliability and operations

**Q: What if there is no Wi-Fi adapter, netsh fails, or output is garbage?**
The scan reports an error instead of crashing: adapter absence, command
timeout, non-zero exit, empty output and malformed/partial output are all
tested (`tests/integration/test_reliability.py`, fixtures for each case).
Failures are visible in the status bar and log.

**Q: What if the database fails mid-run?**
Storage failures surface as a failed scan report (status bar + log), the loop
keeps running, and monitoring recovers on the next successful scan. The fix
that guarantees this (`ScanPipeline.run()` never raises) is pinned by
regression tests.

**Q: Does the UI stay responsive during monitoring?**
Scanning runs on a worker thread; results reach the GUI through queued Qt
signals. Measured end-to-end pipeline processing is single-digit milliseconds
on the development machine (`docs/performance.md`), far below any scan
interval.

**Q: What does it cost to run?**
Free and offline: Python, PySide6, matplotlib, SQLite, PyInstaller, pytest,
ruff — all open source. No account, licence key, subscription or API token
exists in the codebase.

**Q: How do you rebuild it reproducibly?**
`scripts\build.ps1` runs lint, tests and PyInstaller from one spec file and
refuses to package a failing tree. See `docs/packaging.md`.

---

## Testing and quality

**Q: Do the tests require live Wi-Fi?**
No. Every test uses fixtures, fakes or Qt's offscreen platform; the single
live test skips itself gracefully when no adapter exists. The suite runs on a
machine with no wireless hardware.

**Q: What is covered?**
Models, BSSID/security normalization, parser (valid, malformed, empty,
binary junk), scanner command handling (mocked runner), detection rules and
engine state, scoring arithmetic, storage schema/repositories/migrations,
alert dedupe/escalation/cooldown/workflow, export, configuration lifecycle,
monitoring lifecycle/restart/failure paths, settings application, and GUI
smoke (navigation, scans, dialogs, settings round-trip).

**Q: Who reviewed the security posture?**
`SECURITY.md` documents the review (subprocess, storage, files, logs, scope)
and `docs/quality-audit.md` records the prioritized issues found during the
final audit together with their fixes.

---

## Demonstration integrity

**Q: Is the demo rigged?**
The demo either uses owned lab equipment broadcast live, or — when
transmission is not allowed — drives the identical code path from recorded
`netsh` output (`tests/fixtures/`), which is stated openly in
`DEMO_SCRIPT.md`. No hidden hand-edited data enters the database during the
demo.

**Q: What will you do if something breaks mid-demo?**
Every stage has a fallback: fixture-driven test run, packaged vs. source
launch, and a fresh data directory. `DEMO_CHECKLIST.md` lists the checks and
recoveries in order.

**Q: What are the honest limitations?**
Passive-only visibility (it cannot see clients, traffic, or hidden SSIDs'
owners), heuristic scoring (no attribution or intent), English `netsh` label
dependence, single-machine scope, and no remediation capability — by design.
