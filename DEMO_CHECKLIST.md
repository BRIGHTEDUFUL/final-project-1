# Demonstration Checklist

Work top to bottom. Every box must be checked *before* the audience arrives;
the "during" section is the run-of-show tick list.

## Authorisation and safety

- [ ] Written permission / ownership confirmed for every access point and
      client device used in the lab (record where it is filed).
- [ ] Demo network is isolated from production or customer traffic.
- [ ] SSIDs used are obviously lab-owned (e.g. `LabNet`), not real brand or
      corporate names that could be confused with a live incident.
- [ ] No third-party network will be transmitted to, associated with, or
      altered. No jamming, deauth or injection equipment is present.
- [ ] Planned restore step noted: if the anomaly device's security settings
      are weakened for the downgrade scenario, they will be restored after.

## Environment

- [ ] Demo PC on Windows 10/11 with a working Wi-Fi adapter (verify with
      `netsh wlan show interfaces`).
- [ ] Power plan = performance, notifications (Focus Assist) configured so
      the app's toast is visible but no unrelated pop-ups appear.
- [ ] Screen scaling set for the venue (UI is readable at 100–150%).
- [ ] Demo folder available: packaged `dist\RogueAPHunter\` **and** the
      source checkout with `.venv`.
- [ ] Spare data directory wiped for a clean first-scan demonstration:
      stop the app, then
      `Remove-Item "$env:LOCALAPPDATA\Rogue AP Hunter" -Recurse -Force`.

## Software verification (run these on demo day)

- [ ] `.\.venv\Scripts\ruff.exe check .` → clean.
- [ ] `.\.venv\Scripts\pytest.exe` → all tests pass (note the count).
- [ ] `.\scripts\build.ps1 -Clean` → build completes (or a freshly built
      `dist\RogueAPHunter\` from today is present).
- [ ] Packaged smoke test:
      `& .\dist\RogueAPHunter\RogueAPHunter.exe --version` → exit 0.
- [ ] Packaged launch opens the window; Dashboard shows `not yet scanned`.

## Lab anomaly prepared

- [ ] Access point A broadcasting `LabNet` with its approved BSSID known.
- [ ] Device B (owned hotspot/travel router) ready to broadcast `LabNet`,
      currently **off**.
- [ ] Baseline registered in **Trusted networks**: SSID, approved BSSID,
      expected security, note `demo baseline`.
- [ ] Expected scores written on a card for reference
      (duplicate 25 + unknown 20 [+ signal 5] → 45–50 Suspicious;
      + downgrade 30 → High/Critical).

## Materials

- [ ] `DEMO_SCRIPT.md` (run of show), `DEFENSE_QA.md` (anticipated
      questions), this checklist.
- [ ] `docs/detection-methodology.md` and `SECURITY.md` open in tabs for
      reference.
- [ ] Fallback path rehearsed: `pytest tests\integration -v` (fixture-driven)
      and `python scripts\benchmark.py` (measured numbers).
- [ ] Offline fallback rehearsed if the venue forbids transmitting.

---

## During the demo

- [ ] 1. Ethics/scope statement first (owned/authorised equipment only).
- [ ] 2. Baseline: trusted network added, scan runs, no open alerts.
- [ ] 3. Anomaly: device B on → new alert with severity + score.
- [ ] 4. Explainability: Investigation shows facts, reasons, signal history,
      BSSID history, alert history.
- [ ] 5. Settings: weights/thresholds shown as configurable, save applies.
- [ ] 6. Workflow: acknowledge → resolve → record remains in History.
- [ ] 7. Export: alerts CSV opened in a spreadsheet.
- [ ] 8. Persistence proof: restart app, history intact.
- [ ] 9. Close: limitations stated, device B off, lab config restored.

## After

- [ ] Device B disabled, access point A restored to its original settings.
- [ ] Demo data wiped or retained deliberately (state which).
- [ ] Questions captured; anything unanswerable logged as a follow-up issue
      rather than improvised.
