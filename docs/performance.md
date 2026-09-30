# Performance Notes

This document records **measured** performance of Rogue AP Hunter's core
(non-GUI) code paths. All numbers come from the offline benchmark harness
[`scripts/benchmark.py`](../scripts/benchmark.py) and were produced on the
development machine described below. Nothing here is estimated or taken from a
spec sheet — re-running the commands in §12 reproduces every figure.

---

## 1. Measurement environment

> **All numbers were measured on the development machine below.** Results on
> other hardware will differ.

| Item | Value |
|------|-------|
| Machine | Dell Inc. XPS 15 9560 |
| CPU | Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz (4 cores / 8 logical processors) |
| RAM | 34,204,200,960 bytes ≈ **31.86 GiB** |
| OS | Windows 11 (Windows-11-10.0.26200-SP0), AMD64 |
| Python | CPython **3.14.3** (MSC v.1944 64 bit (AMD64)) |
| Database | SQLite via `app.storage.Database` — WAL journal, foreign keys on (identical to production) |
| Benchmark run | 2026-09-30T03:18:30+00:00 (UTC) |

CPU and RAM as reported by Windows:

```powershell
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory
```

```
Name              : Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
NumberOfCores     : 4
NumberOfLogicalProcessors : 8
MaxClockSpeed     : 2801
Manufacturer      : Dell Inc.
Model             : XPS 15 9560
TotalPhysicalMemory : 34204200960
```

## 2. Methodology

The harness is deliberately **offline and headless**: no wireless adapter, no
`netsh` subprocess, no Qt event loop.

- **Scan input** comes from the checked-in fixture
  `tests/fixtures/netsh_show_networks_multi.txt` (1,052 bytes, 3 SSIDs / 4
  radios) plus `tests/fixtures/netsh_show_interfaces_connected.txt`, fed
  through `tests.support.FakeScanner` (the harness imports it and falls back to
  a local copy if `tests/` is unavailable).
- **End-to-end phase** runs the real `app.services.ScanPipeline.run()`:
  session start → interface lookup → parse → detection → scoring → persist →
  alert handling → periodic retention prune → session finish. 5 untimed warm-up
  scans run first so the BSSID-history cache and SQLite page cache are hot.
- **Storage phase** uses a fresh temporary SQLite file per phase with the real
  `Database`/repository classes (every statement is a committed transaction,
  exactly as in production). Alert/score batch payloads are built *before*
  timing so model validation is not attributed to the write.
- **Alert phase** drives `AlertManager.record()` (the manager's per-alert entry
  point — there is no `handle()` method) through the three transition kinds:
  *created*, *escalated*, *deduplicated repeat*, using a counting notifier so
  notification delivery and cooldown suppression are both exercised.
- **Memory phase** runs 300 scans through one pipeline instance while
  `tracemalloc` records Python allocations and, on Windows,
  `GetProcessMemoryInfo` (psapi.dll) records the working set; RSS is sampled
  after every scan for start/end/peak.
- **Timing**: `time.perf_counter()` per call; statistics via `statistics`;
  p95 is the nearest-rank percentile. App logging is set to `CRITICAL` during
  the run so the table stays readable (failure paths still raise).
- Standard library only (no numpy/matplotlib).

### What the benchmark does *not* include

- The `netsh wlan` subprocess and the OS WLAN scan itself. That cost is
  machine/driver dependent and dominates real scan latency; every figure below
  is the **application-side** cost layered on top of it.
- GUI rendering, notification toasts (PowerShell), and disk contention from
  other applications.

## 3. Scan-processing time (end-to-end pipeline)

`ScanPipeline.run()` with the fake scanner, **100 timed iterations** after 5
warm-ups (database accumulating: 424 observation rows by the end):

| n | min | median | p95 | max | mean | rate |
|---|-----|--------|-----|-----|------|------|
| 100 | 4.093 ms | **6.204 ms** | 8.424 ms | 9.858 ms | 6.186 ms | ~162 scans/s |

Notes from the run: 4 radios parsed per scan, 2 scored identities per scan
(steady state — the *unknown-BSSID* rule quiets down once history exists), and
the every-20th-scan retention prune fired 5 times inside the 106 scans that
were executed, so the tail (p95/max) includes prune scans.

**Proxy for UI "Scan once":** `shell.scan_once()` blocks the calling slot for
exactly this duration plus one `netsh` call (see §7). Application-side work is
~6 ms median, ~8.4 ms at p95.

## 4. Parser throughput

`parse_visible_networks_as_observations()` on the multi-network fixture,
**100 iterations**:

| n | min | median | p95 | max | mean | rate |
|---|-----|--------|-----|-----|------|------|
| 100 | 0.118 ms | **0.147 ms** | 0.345 ms | 0.547 ms | 0.185 ms | ~5,411 parses/s |

Each parse yields 4 `NetworkObservation` models from 1,052 bytes of text. The
parser is ~2.4% of the end-to-end pipeline time — detection/scoring and SQLite
writes dominate.

## 5. Database write time

Single-row writes (100 timed calls each) and 1,000-row batches (5 timed
repeats), all on a temporary SQLite file:

| Operation | n | min | median | p95 | max | rate |
|-----------|---|-----|--------|-----|-----|------|
| `ObservationRepository.add` (single) | 100 | 0.376 ms | **0.584 ms** | 1.283 ms | 1.748 ms | ~1,481 rows/s |
| `ObservationRepository.add_many` (batch of 1000) | 5 | 11.775 ms | **13.538 ms** | 31.053 ms | 31.053 ms | ~58 batches/s |
| └ derived per row of the batch | 5 | 0.012 ms | **0.014 ms** | 0.031 ms | 0.031 ms | ~57,600 rows/s |
| `AlertRepository.add` (single) | 100 | 0.366 ms | **0.569 ms** | 1.525 ms | 1.764 ms | ~1,480 alerts/s |
| `AlertRepository.add` × 1000 sequential | 5 | 666.8 ms | **687.2 ms** | 697.8 ms | 697.8 ms | ~1,455 alerts/s |
| `RiskScoreRepository.add` (single) | 100 | 0.340 ms | **0.439 ms** | 1.243 ms | 1.623 ms | ~1,870 scores/s |
| `RiskScoreRepository.add` × 1000 sequential | 5 | 586.0 ms | **1,012.8 ms** | 1,573.8 ms | 1,573.8 ms | ~987 scores/s |

Interpretation:

- One scan writes 4 observation rows **in a single `add_many` transaction**
  (the only batch API the repositories expose) — well under 1 ms of work at the
  per-row rate above — plus 2 risk-score rows (~0.9 ms) and up to 2 alert
  records (~1.5 ms). Storage is therefore only a minority part of the 6.2 ms
  pipeline median in §3.
- `AlertRepository` and `RiskScoreRepository` have **no batch API**: a burst of
  1000 sequential inserts costs ~0.7 s (alerts) to ~1.0 s (scores), i.e. one
  fsync-style commit per row. The monitoring loop never approaches this rate
  (at most a handful of rows per scan), but bulk imports should prefer
  `ObservationRepository.add_many`.

## 6. Alert processing latency

`AlertManager.record()` across the three transition kinds, 100 identities × 3
calls (a counting notifier is installed; cooldown set to the production
default of 60 s):

| Transition | n | min | median | p95 | max | rate |
|------------|---|-----|--------|-----|-----|------|
| *created* (first sighting: dedup lookup + INSERT + first notification) | 100 | 0.451 ms | **0.754 ms** | 1.738 ms | 2.139 ms | ~1,196/s |
| *escalated* (dedup lookup + occurrence UPDATE; notification cooldown-gated) | 100 | 0.500 ms | **0.779 ms** | 1.888 ms | 2.415 ms | ~1,100/s |
| *repeat, deduplicated* (dedup lookup + occurrence UPDATE, no notification) | 100 | 0.464 ms | **0.714 ms** | 1.845 ms | 2.289 ms | ~1,182/s |
| all calls combined | 300 | 0.451 ms | **0.755 ms** | 1.822 ms | 2.415 ms | ~1,158/s |

**Observed transitions:** 100 created, 100 escalated, 100 deduplicated repeats;
**100 notifications delivered**.

### Notification cooldown (verified in source)

`app/alerts/manager.py` defines
`DEFAULT_MIN_NOTIFICATION_INTERVAL_SECONDS = 60` and passes it as the default
of `AlertManager.__init__(min_notification_interval=...)`. The cooldown key is
`(ssid, bssid, alert_type)` — i.e. **per alert identity**, not global — and
notifications are only attempted for transitions that are *meaningful*
(created or escalated) at severity ≥ `notify_below_severity`
(default `Severity.SUSPICIOUS`).

The benchmark shows this working: each identity's first sighting notified
once (100 deliveries); the escalation that followed within the same second was
suppressed by the 60-second interval; the third call was a deduplicated repeat
and never reached the notifier. So during a burst the alert *state* updates
every scan (~0.8 ms), while *desktop notifications* are rate-limited to at
most one per identity per minute.

## 7. UI responsiveness notes

- **The Qt event loop is only ever touched on the GUI thread.** Monitoring
  runs on a daemon worker thread (`rogue-ap-monitor` in
  `app/services/monitoring.py`); `MonitoringService` callbacks run there and
  are marshalled to the UI thread through `app/ui/bridge.py` (`MonitorBridge`),
  which emits `report_ready`, `error_raised`, `monitoring_changed` and
  `alert_count_changed` Qt signals. Qt queues cross-thread signal deliveries,
  so the receiving slots always execute on the GUI thread.
- **"Scan once" blocks only its own slot for one pipeline pass.**
  `shell.scan_once()` disables the button, calls
  `MonitoringService.scan_once()` synchronously and re-enables it. The
  measured pipeline time — **6.2 ms median, 8.4 ms p95** (§3) — is the
  application-side proxy; the visible stall additionally includes one `netsh`
  subprocess call, which the offline benchmark intentionally excludes.
- **Table models reset atomically.** `TableModel.set_rows()` in
  `app/ui/table_models.py` wraps every data replacement in
  `beginResetModel()`/`endResetModel()`, so views repaint once per update
  rather than once per row — row-count growth does not translate into
  proportional GUI work.
- Periodic scans never touch the UI thread at all: their reports arrive as
  queued signals, so a slow scan cannot freeze painting or input handling.

## 8. Memory behaviour during prolonged monitoring

300 simulated scans through one pipeline instance (5 warm-ups first, then
`tracemalloc` enabled and RSS sampled after every scan):

| Metric | Start | End | Peak | Growth |
|--------|-------|-----|------|--------|
| `tracemalloc` (live Python allocations) | 0.0 KiB | **48.1 KiB** | 195.2 KiB (peak) | **+48.1 KiB over 300 scans (≈0.16 KiB/scan)** |
| Process working set (`GetProcessMemoryInfo`) | 34,556.0 KiB | **36,424.0 KiB** | 36,424.0 KiB | **+1,868.0 KiB (≈6.2 KiB/scan)** |

Supporting facts from the same run:

- Wall time for the 300 scans: 3.34 s → 11.1 ms/scan (about 2× the untimed
  6.2 ms; `tracemalloc` instrumentation accounts for the difference).
- Rows written: 1,220 observations (305 scans × 4 radios) and 305 scan
  sessions — i.e. the growth in §8 is *with* an ever-growing SQLite file.
- `DetectionEngine.persistence_counts` ended with **2 entries** and the
  pipeline tracked **4 distinct BSSIDs** — both identity-keyed, not
  scan-count-keyed.

Interpretation: live Python allocations plateau at a few tens of KiB; the
~1.8 MiB RSS rise over 300 scans is allocator/SQLite page caching, not an
object leak, and it does not scale with scan count in this test.

### In-memory state: what is and is not unbounded

Checked against the source, as required for an honest report:

- `app/detection/engine.py` (`DetectionEngine._consecutive`): **not
  unbounded.** After every `evaluate()` the engine deletes counters for
  identities that did *not* produce findings in that scan, so the dict holds at
  most one entry per identity currently producing findings. Counters reset via
  `DetectionEngine.reset()`.
- `ScanPipeline._known_bssids` (`app/services/monitoring.py`): the frozenset
  accumulates every distinct BSSID ever seen for the process lifetime and is
  **never trimmed when retention pruning removes old rows** — it only grows
  with the number of *distinct* radios observed (4 in this benchmark), never
  with the number of scans.
- `AlertManager._last_notified` (`app/alerts/manager.py`): one entry per
  notified `(ssid, bssid, alert_type)` identity, **never evicted** — again
  bounded by distinct alerting identities, not by uptime.

So there is no scan-count-driven leak; the true growth drivers are the number
of distinct networks in the environment and the SQLite row counts (§9).

## 9. Retention, pruning and expected impact

- `Config.data_retention_days` defaults to **90** (validated range 1–3650) —
  `app/core/config.py`.
- `ScanPipeline._maybe_prune()` applies the window every
  `DEFAULT_PRUNE_EVERY_SCANS = 20` scans (`app/services/monitoring.py`), using
  a cutoff of `utcnow() - timedelta(days=data_retention_days)` and calling, in
  order, `ObservationRepository.prune()`, `AlertRepository.prune()` and
  `RiskScoreRepository.prune()` (`app/storage/repositories.py`).
  - `ObservationRepository.prune` deletes **all** observations older than the
    cutoff (indexed on `observed_at`).
  - `RiskScoreRepository.prune` deletes **all** score rows older than the
    cutoff (indexed on `(ssid, bssid, created_at)`).
  - `AlertRepository.prune` deletes only alerts with `status != 'active'` —
    **open alerts are never pruned** until they are acknowledged or resolved.
- **Expected impact:** three `DELETE`s every 20 scans is negligible — the
  measured pipeline median of 6.2 ms already *includes* the 5 prune passes that
  occurred during the 106-scan run (§3).
- **Expected data volume** (arithmetic from the measured 4 radios/scan): at
  the default 15-s interval one day produces 5,760 scans ≈ 23,040 observation
  rows (~2.07 M rows over the 90-day window before pruning kicks in); at the
  5-s minimum interval that is ~69,120 rows/day. Risk-score rows are bounded
  the same way. Alert rows are bounded only by user workflow: until alerts are
  acknowledged/resolved they accumulate indefinitely — that is the one
  retention gap worth knowing about.

## 10. Honest interpretation for a 5–15 s scan interval

- The scan interval is configurable between **5 s (minimum) and 3600 s
  (maximum)** with a default of **15 s** (`app/core/config.py`:
  `MIN_SCAN_INTERVAL_SECONDS`, `MAX_SCAN_INTERVAL_SECONDS`,
  `scan_interval_seconds = 15`).
- At the measured **6.2 ms median** (8.4 ms p95) of application-side work, one
  scan consumes about **0.04 %** of a 15-s interval and **0.12 %** of the 5-s
  minimum. Even the slowest single scan seen across all runs (29.7 ms, cold
  first run) is only ~0.6 % of the shortest interval, so the monitoring loop is
  idle >99 % of the time in the worst case observed. CPU headroom is not a
  constraint; the real interval cost is the `netsh`/OS WLAN scan, which this
  benchmark excludes.
- Alerts and scores are available to the UI within the same scan: the alert
  path adds **~0.8 ms median per call** (up to ~1.6 ms while the machine was
  under concurrent load — see §11), so a 15-s interval means detection →
  visible alert in essentially one scan cycle.
- Memory stays flat in scan count: **+48 KiB live Python allocations and
  ~1.8 MiB RSS across 300 scans**; in-memory state is keyed by network
  identity (§8), so a long-running session on a fixed site stays stable. The
  growth levers are distinct networks seen and unpruned SQLite rows.
- Storage is comfortably fast for the workload: ~1–2 ms of writes inside a
  6.2 ms scan. The only slow path is bulk back-filling (no batch API on
  alerts/scores: ~0.7–1.0 s per 1000 rows).
- **Known limits to watch:** active alerts are never pruned; the in-memory
  `known_bssids`/`_last_notified` sets never shrink during a session; and
  repeated 1000-row insert batches showed the largest run-to-run variance
  (§11).

## 11. Run-to-run variance

Four full runs were made on this machine; the tables above quote the
2026-09-30T03:18:30+00:00 run.

- A repeat run one minute earlier (03:17:19) matched closely: parser median
  0.161 ms, pipeline median 6.312 ms (p95 8.543 ms), single-alert write
  0.577 ms, `AlertManager.record` median 0.790 ms, tracemalloc end 52.2 KiB,
  RSS growth 2,068 KiB.
- A confirmation run after the quality gate (03:23:58, while the machine was
  additionally busy with other builds) again gave pipeline median **6.299 ms**
  and tracemalloc end **48.1 KiB** — but the combined `AlertManager.record`
  median rose to 1.580 ms and RSS growth came out at 1,768 KiB.
- The very first run (cold caches, app logging still enabled) showed a 12.6 ms
  pipeline median.

Stable across runs: pipeline median 6.2–6.3 ms (12.6 ms cold), parser median
0.15–0.16 ms, tracemalloc live growth 48 KiB, RSS growth 1.8–2.1 MiB.
Unstable — treat as noise: sub-millisecond write/record medians (0.4–1.6 ms
depending on machine load) and the 1,000-row batch totals (alerts 687–1,389 ms,
scores 616–1,013 ms). None of this variance changes the conclusions: the worst
pipeline *median* observed was 6.3 ms (12.6 ms cold) and the worst single
scan was 29.7 ms — still well under 1 % of the shortest configured interval.

## 12. Reproducing these numbers

From the repository root on the development machine:

```powershell
# full benchmark with machine-readable output (defaults: 100 iterations, 300 scans, 1000-row batches)
.\.venv\Scripts\python.exe scripts\benchmark.py --json benchmark-results.json

# explicit parameters, same as the run documented above
.\.venv\Scripts\python.exe scripts\benchmark.py --iterations 100 --scans 300 --batch 1000 --json benchmark-results.json

# quick sanity run
.\.venv\Scripts\python.exe scripts\benchmark.py --iterations 20 --scans 50

# hardware details quoted in §1
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory

# quality gate (lint + tests) — must stay green after any change
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pytest.exe
```

The harness exits `0` on success and prints one table per phase plus the
environment header; `--json` additionally writes the full results (environment,
parameters, per-metric min/median/p95/max/mean, alert transition counts and
memory figures) as JSON for tooling.
