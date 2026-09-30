"""Offline performance benchmark for Rogue AP Hunter.

Measures the real application code paths without a wireless adapter and
without the Qt GUI: end-to-end scan processing (``ScanPipeline.run`` fed by a
fake scanner and the recorded ``netsh`` fixture), SQLite write latency, alert
processing latency, parser throughput and memory behaviour during prolonged
monitoring.

Usage::

    .\\.venv\\Scripts\\python.exe scripts\\benchmark.py
    .\\.venv\\Scripts\\python.exe scripts\\benchmark.py --iterations 50 --scans 100
    .\\.venv\\Scripts\\python.exe scripts\\benchmark.py --json benchmark-results.json

Only the standard library and the project's own modules are used; timing is
done with :func:`time.perf_counter` and statistics with :mod:`statistics`.
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import math
import os
import platform
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
NETWORKS_FIXTURE = "netsh_show_networks_multi.txt"
INTERFACES_FIXTURE = "netsh_show_interfaces_connected.txt"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.alerts import AlertManager, NullNotifier  # noqa: E402
from app.core.config import Config  # noqa: E402
from app.models import Alert, AlertType, NetworkObservation, Severity, utcnow  # noqa: E402
from app.parser import parse_visible_networks_as_observations  # noqa: E402
from app.scanner.raw import RawScanResult  # noqa: E402
from app.services import ScanPipeline, ScanReport  # noqa: E402
from app.storage import (  # noqa: E402
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    TrustedNetworkRepository,
)

# Keep the report readable: the pipeline logs one line per scan and the alert
# manager logs per escalation at WARNING level. Failures are surfaced as
# exceptions by the harness, so nothing is silently swallowed here.
logging.getLogger("app").setLevel(logging.CRITICAL)

__all__ = [
    "AlertStats",
    "EnvironmentInfo",
    "MemoryResult",
    "TimingResult",
    "main",
]

WARMUP_SCANS = 5
BATCH_REPEATS = 5
PCTL = 0.95
BSSID_PREFIX = (0x02, 0x00, 0x00)  # locally administered, unicast


# --------------------------------------------------------------------- results


@dataclass(frozen=True)
class TimingResult:
    """Timing statistics (milliseconds) for one benchmarked operation."""

    name: str
    count: int
    min_ms: float
    median_ms: float
    p95_ms: float
    max_ms: float
    mean_ms: float
    total_seconds: float
    notes: str = ""

    @property
    def per_second(self) -> float:
        """Mean operations per second derived from the mean duration."""
        return 1000.0 / self.mean_ms if self.mean_ms > 0 else float("inf")


@dataclass(frozen=True)
class AlertStats:
    """What the alert benchmark observed (transitions and notifications)."""

    created: int
    escalated: int
    deduplicated: int
    notifications_delivered: int
    min_notification_interval_seconds: int


@dataclass(frozen=True)
class MemoryResult:
    """Memory footprint across a prolonged simulated monitoring run."""

    scans: int
    wall_seconds: float
    tracemalloc_start_kb: float
    tracemalloc_end_kb: float
    tracemalloc_peak_kb: float
    rss_start_kb: float | None
    rss_end_kb: float | None
    rss_peak_kb: float | None
    observation_rows: int
    session_rows: int
    engine_persistence_entries: int
    known_bssids: int


@dataclass(frozen=True)
class EnvironmentInfo:
    """Machine and interpreter the numbers were measured on."""

    timestamp: str
    os: str
    machine: str
    python: str
    cpu: str
    logical_cpus: int
    total_ram_gb: float | None


# ---------------------------------------------------------------- environment


def _cpu_name() -> str:
    """Best-effort CPU model string (Windows registry, then platform hints)."""
    if sys.platform == "win32":
        try:
            import winreg

            key_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value, _type = winreg.QueryValueEx(key, "ProcessorNameString")
                del _type
            if isinstance(value, str) and value.strip():
                return value.strip()
        except OSError:
            pass
    return platform.processor() or platform.machine() or "unknown"


def _total_ram_bytes() -> int | None:
    """Total physical RAM in bytes, or ``None`` when it cannot be read."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class MemoryStatusEx(ctypes.Structure):  # noqa: N818 - Win32 MEMORYSTATUSEX
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_uint64),
                ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64),
                ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64),
                ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return int(status.ullTotalPhys)
        return None
    try:
        return int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (ValueError, OSError):
        return None


def environment_info() -> EnvironmentInfo:
    """Collect the environment header printed alongside the results."""
    ram = _total_ram_bytes()
    return EnvironmentInfo(
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
        os=platform.platform(),
        machine=platform.machine() or "unknown",
        python=f"{platform.python_implementation()} {platform.python_version()} ({platform.python_compiler()})",
        cpu=_cpu_name(),
        logical_cpus=os.cpu_count() or 0,
        total_ram_gb=round(ram / (1024**3), 2) if ram else None,
    )


# ------------------------------------------------------------- RSS utilities


def _make_rss_reader() -> Callable[[], int | None]:
    """Return a callable reading the current resident set size in bytes."""
    if sys.platform == "win32":
        return _windows_rss_reader()
    return _unix_rss_reader()


def _windows_rss_reader() -> Callable[[], int | None]:
    """Working-set size via ``GetProcessMemoryInfo`` (psapi.dll)."""
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):  # noqa: N818 - Win32 structure
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    try:
        psapi = ctypes.WinDLL("psapi")
        kernel32 = ctypes.WinDLL("kernel32")
    except OSError:
        return lambda: None

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(ProcessMemoryCounters)
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.GetCurrentProcess()

    def read() -> int | None:
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize)

    return read


def _unix_rss_reader() -> Callable[[], int | None]:
    """Current RSS from ``/proc/self/statm`` (Linux) or peak via ``rusage``."""
    statm = Path("/proc/self/statm")
    if statm.is_file():

        def read_proc() -> int | None:
            fields = statm.read_text(encoding="ascii").split()
            if len(fields) < 2:
                return None
            return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")

        return read_proc

    try:
        import resource
    except ImportError:
        return lambda: None

    def read_rusage() -> int | None:
        # ru_maxrss is bytes on macOS and kibibytes on other Unixes.
        factor = 1 if sys.platform == "darwin" else 1024
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * factor

    return read_rusage


# ------------------------------------------------------------------ helpers


def _fixture_text(name: str) -> str:
    """Read a recorded ``netsh`` fixture shipped with the test suite."""
    path = FIXTURES_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"missing benchmark fixture: {path}")
    return path.read_text(encoding="utf-8")


class _LocalFakeScanner:
    """Fallback copy of ``tests.support.FakeScanner`` for stripped checkouts."""

    def __init__(
        self,
        network_text: str = "",
        interface_text: str = "",
        *,
        usable: tuple[bool, str] = (True, "wireless interface available"),
        scan_ok: bool = True,
        delay: float = 0.0,
    ) -> None:
        self.network_text = network_text
        self.interface_text = interface_text
        self.usable = usable
        self.scan_ok = scan_ok
        self.delay = delay
        self.scan_calls = 0
        self.interface_calls = 0

    def available(self) -> tuple[bool, str]:
        """Report the canned availability result."""
        return self.usable

    def scan(self) -> RawScanResult:
        """Return the canned network scan output without invoking netsh."""
        self.scan_calls += 1
        if self.delay:
            time.sleep(self.delay)
        return RawScanResult.create(
            ("netsh", "wlan", "show", "networks", "mode=bssid"),
            self.network_text,
            "" if self.scan_ok else "command failed",
            0 if self.scan_ok else 1,
            0.01,
        )

    def show_interfaces(self) -> RawScanResult:
        """Return the canned interface output without invoking netsh."""
        self.interface_calls += 1
        return RawScanResult.create(
            ("netsh", "wlan", "show", "interfaces"),
            self.interface_text,
            "",
            0,
            0.01,
        )


def _fake_scanner_type() -> Any:
    """Return ``tests.support.FakeScanner`` when importable, else the local copy."""
    try:
        from tests.support import FakeScanner
    except ModuleNotFoundError as exc:
        if exc.name is None or not exc.name.split(".")[0] == "tests":
            raise
        return _LocalFakeScanner
    return FakeScanner


class _CountingNotifier:
    """Notifier stub that counts deliveries instead of showing toasts."""

    def __init__(self) -> None:
        self.calls = 0

    def notify(self, alert: Alert) -> bool:
        """Count the notification and report success."""
        del alert
        self.calls += 1
        return True


def _bssid(index: int) -> str:
    """Deterministic, valid BSSID for benchmark identity ``index``."""
    return (
        f"{BSSID_PREFIX[0]:02x}:{BSSID_PREFIX[1]:02x}:{BSSID_PREFIX[2]:02x}:"
        f"{(index >> 16) & 0xFF:02x}:{(index >> 8) & 0xFF:02x}:{index & 0xFF:02x}"
    )


def _observation(index: int) -> NetworkObservation:
    """Build a realistic observation row for storage benchmarks."""
    return NetworkObservation(
        ssid=f"Bench-{index % 32:02d}",
        bssid=_bssid(index),
        signal_strength=30 + (index % 60),
        security="WPA2-Personal",
        channel=1 + (index % 13),
        observed_at=utcnow(),
    )


def _alert(index: int, *, score: int) -> Alert:
    """Build an alert for the alert-processing benchmark."""
    return Alert.from_score(
        ssid=f"Bench-{index:04d}",
        bssid=_bssid(index),
        alert_type=AlertType.DUPLICATE_SSID,
        risk_score=score,
        reasons=(f"benchmark identity {index}",),
    )


def _timing(name: str, samples: Sequence[float], *, notes: str = "") -> TimingResult:
    """Summarise per-call durations (seconds) into a :class:`TimingResult`."""
    if not samples:
        raise ValueError(f"no samples collected for {name}")
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, max(0, math.ceil(PCTL * len(ordered)) - 1))
    mean = statistics.fmean(samples)
    return TimingResult(
        name=name,
        count=len(samples),
        min_ms=min(samples) * 1000.0,
        median_ms=statistics.median(samples) * 1000.0,
        p95_ms=ordered[p95_index] * 1000.0,
        max_ms=max(samples) * 1000.0,
        mean_ms=mean * 1000.0,
        total_seconds=sum(samples),
        notes=notes,
    )


def _require_ok(report: ScanReport) -> None:
    """Fail loudly when the pipeline reports an error (benchmarks must be real)."""
    if not report.ok:
        raise RuntimeError(f"scan pipeline failed during benchmark: {report.error}")


# ------------------------------------------------------------ benchmark phases


@dataclass
class _Harness:
    """Everything one benchmarking context needs to drive the pipeline."""

    pipeline: ScanPipeline
    database: Database
    observations: ObservationRepository
    sessions: ScanSessionRepository
    alerts: AlertRepository
    scores: RiskScoreRepository
    manager: AlertManager
    scanner: Any


@contextmanager
def _pipeline_harness(db_path: Path, *, notifier: Any = None) -> Iterator[_Harness]:
    """Build a complete scan pipeline backed by a temporary SQLite file."""
    scanner_type = _fake_scanner_type()
    scanner = scanner_type(
        network_text=_fixture_text(NETWORKS_FIXTURE),
        interface_text=_fixture_text(INTERFACES_FIXTURE),
    )
    database = Database(db_path).open()
    try:
        config = Config()
        observations = ObservationRepository(database)
        sessions = ScanSessionRepository(database)
        trusted = TrustedNetworkRepository(database)
        alerts = AlertRepository(database)
        scores = RiskScoreRepository(database)
        manager = AlertManager(
            alerts,
            config=config,
            notifier=notifier if notifier is not None else NullNotifier(),
        )
        pipeline = ScanPipeline(
            scanner=scanner,
            observations=observations,
            sessions=sessions,
            trusted=trusted,
            scores=scores,
            alert_repository=alerts,
            alert_manager=manager,
            config=config,
        )
        yield _Harness(
            pipeline=pipeline,
            database=database,
            observations=observations,
            sessions=sessions,
            alerts=alerts,
            scores=scores,
            manager=manager,
            scanner=scanner,
        )
    finally:
        database.close()


def bench_parser(text: str, iterations: int) -> tuple[TimingResult, int]:
    """Parser throughput: fixture text -> ``NetworkObservation`` models."""
    stamp = utcnow()
    for _ in range(3):
        parse_visible_networks_as_observations(text, observed_at=stamp)

    observations = 0
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        parsed = parse_visible_networks_as_observations(text, observed_at=stamp)
        samples.append(time.perf_counter() - started)
        observations = len(parsed)
    notes = f"{observations} observations per parse of {len(text)} fixture bytes"
    return _timing("parser.parse_visible_networks_as_observations", samples, notes=notes), observations


def bench_pipeline(iterations: int, db_path: Path) -> TimingResult:
    """End-to-end ``ScanPipeline.run()``: scan -> parse -> detect -> score -> persist -> alert."""
    with _pipeline_harness(db_path) as harness:
        for _ in range(WARMUP_SCANS):
            _require_ok(harness.pipeline.run())

        samples: list[float] = []
        report = harness.pipeline.run()
        for _ in range(iterations):
            started = time.perf_counter()
            report = harness.pipeline.run()
            samples.append(time.perf_counter() - started)
            _require_ok(report)

        notes = (
            f"{report.network_count} radios/scan, {len(report.assessments)} scored identities, "
            f"{harness.observations.count()} rows after {iterations + WARMUP_SCANS + 1} scans"
        )
    return _timing("pipeline.ScanPipeline.run (end-to-end)", samples, notes=notes)


def bench_db_writes(iterations: int, batch_rows: int, db_path: Path) -> list[TimingResult]:
    """Storage latency: single-row writes and 1000-row batches per repository."""
    results: list[TimingResult] = []
    with Database(db_path) as database:
        observations = ObservationRepository(database)
        alerts = AlertRepository(database)
        scores = RiskScoreRepository(database)

        # Observations, single row.
        samples: list[float] = []
        for index in range(iterations):
            row = _observation(index)
            started = time.perf_counter()
            observations.add(row)
            samples.append(time.perf_counter() - started)
        results.append(
            _timing(
                "storage.ObservationRepository.add (single)",
                samples,
                notes="one INSERT in its own transaction (WAL)",
            )
        )

        # Observations, batch (the API the pipeline uses: add_many).
        batch = [_observation(100_000 + index) for index in range(batch_rows)]
        batch_samples: list[float] = []
        for _ in range(BATCH_REPEATS):
            started = time.perf_counter()
            stored = observations.add_many(batch)
            batch_samples.append(time.perf_counter() - started)
            if stored != batch_rows:
                raise RuntimeError(f"expected {batch_rows} rows stored, got {stored}")
        result = _timing(
            f"storage.ObservationRepository.add_many (batch of {batch_rows})",
            batch_samples,
            notes="single transaction, executemany",
        )
        results.append(result)
        results.append(
            _timing(
                f"storage.ObservationRepository.add_many (per row of {batch_rows})",
                [sample / batch_rows for sample in batch_samples],
                notes="derived: batch total divided by row count",
            )
        )

        # Alerts, single row (repository level; AlertManager is benchmarked below).
        samples = []
        for index in range(iterations):
            alert = _alert(index, score=35)
            started = time.perf_counter()
            alerts.add(alert)
            samples.append(time.perf_counter() - started)
        results.append(
            _timing("storage.AlertRepository.add (single)", samples, notes="one INSERT per alert")
        )

        # Alerts, no batch API: 1000 sequential single inserts in one measurement.
        # Payloads are built before timing so model validation is not measured.
        alert_batch = [_alert(1_000_000 + index, score=35) for index in range(batch_rows)]
        alert_batch_samples: list[float] = []
        for _ in range(BATCH_REPEATS):
            started = time.perf_counter()
            for alert in alert_batch:
                alerts.add(alert)
            alert_batch_samples.append(time.perf_counter() - started)
        results.append(
            _timing(
                f"storage.AlertRepository.add ({batch_rows} sequential inserts)",
                alert_batch_samples,
                notes="no batch API: one transaction per alert",
            )
        )

        # Risk scores, single row.
        samples = []
        for index in range(iterations):
            started = time.perf_counter()
            scores.add(
                ssid=f"Bench-{index % 32:02d}",
                bssid=_bssid(index),
                score=35,
                severity=Severity.SUSPICIOUS,
                reasons=["benchmark score"],
                created_at=utcnow(),
            )
            samples.append(time.perf_counter() - started)
        results.append(
            _timing("storage.RiskScoreRepository.add (single)", samples, notes="one INSERT per score")
        )

        # Risk scores, sequential batch (payloads built before timing).
        score_batch = [
            {
                "ssid": f"Bench-{index % 32:02d}",
                "bssid": _bssid(2_000_000 + index),
                "score": 35,
                "severity": Severity.SUSPICIOUS,
                "reasons": ["benchmark score"],
                "created_at": utcnow(),
            }
            for index in range(batch_rows)
        ]
        score_batch_samples: list[float] = []
        for _ in range(BATCH_REPEATS):
            started = time.perf_counter()
            for payload in score_batch:
                scores.add(**payload)
            score_batch_samples.append(time.perf_counter() - started)
        results.append(
            _timing(
                f"storage.RiskScoreRepository.add ({batch_rows} sequential inserts)",
                score_batch_samples,
                notes="no batch API: one transaction per score",
            )
        )

    return results


def bench_alerts(iterations: int, db_path: Path) -> tuple[list[TimingResult], AlertStats]:
    """Alert processing latency across the three transition kinds.

    The entry point is :meth:`AlertManager.record` (there is no ``handle``):
    first sighting creates, a higher-severity sighting escalates, and repeats
    are deduplicated onto the existing alert.
    """
    notifier = _CountingNotifier()
    created_samples: list[float] = []
    escalated_samples: list[float] = []
    repeat_samples: list[float] = []
    created = escalated = deduplicated = 0

    with Database(db_path) as database:
        repository = AlertRepository(database)
        manager = AlertManager(
            repository,
            config=Config(),
            notifier=notifier,
            min_notification_interval=60,
        )

        for index in range(iterations):
            started = time.perf_counter()
            transition = manager.record(_alert(index, score=35))
            created_samples.append(time.perf_counter() - started)
            if not (transition.created and not transition.escalated):
                raise RuntimeError("expected a 'created' transition on first sighting")
            created += int(transition.created)

        for index in range(iterations):
            started = time.perf_counter()
            transition = manager.record(_alert(index, score=70))
            escalated_samples.append(time.perf_counter() - started)
            if not transition.escalated:
                raise RuntimeError("expected an 'escalated' transition for a higher severity")
            escalated += int(transition.escalated)

        for index in range(iterations):
            started = time.perf_counter()
            transition = manager.record(_alert(index, score=70))
            repeat_samples.append(time.perf_counter() - started)
            if transition.created or transition.escalated:
                raise RuntimeError("expected a deduplicated repeat with no transition")
            deduplicated += 1

        alert_rows = repository.count()

    results = [
        _timing(
            "alerts.AlertManager.record (created)",
            created_samples,
            notes="find_open_match + INSERT + first notification",
        ),
        _timing(
            "alerts.AlertManager.record (escalated)",
            escalated_samples,
            notes="find_open_match + UPDATE; notification gated by 60 s cooldown",
        ),
        _timing(
            "alerts.AlertManager.record (repeat, deduplicated)",
            repeat_samples,
            notes="find_open_match + occurrence UPDATE, no notification",
        ),
        _timing(
            f"alerts.AlertManager.record (all three phases, {alert_rows} stored alerts)",
            [*created_samples, *escalated_samples, *repeat_samples],
            notes="end-to-end per-call latency",
        ),
    ]
    stats = AlertStats(
        created=created,
        escalated=escalated,
        deduplicated=deduplicated,
        notifications_delivered=notifier.calls,
        min_notification_interval_seconds=60,
    )
    return results, stats


def bench_memory(scans: int, db_path: Path) -> MemoryResult:
    """Memory behaviour while running ``scans`` passes through one pipeline."""
    rss = _make_rss_reader()
    with _pipeline_harness(db_path) as harness:
        for _ in range(WARMUP_SCANS):
            _require_ok(harness.pipeline.run())
        gc.collect()

        tracemalloc.start()
        trace_start, _peak = tracemalloc.get_traced_memory()
        rss_start = rss()
        rss_peak = rss_start

        started = time.perf_counter()
        for _ in range(scans):
            _require_ok(harness.pipeline.run())
            current = rss()
            if current is not None:
                rss_peak = current if rss_peak is None else max(rss_peak, current)
        wall = time.perf_counter() - started

        trace_end, trace_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_end = rss()

        return MemoryResult(
            scans=scans,
            wall_seconds=wall,
            tracemalloc_start_kb=trace_start / 1024.0,
            tracemalloc_end_kb=trace_end / 1024.0,
            tracemalloc_peak_kb=trace_peak / 1024.0,
            rss_start_kb=round(rss_start / 1024.0, 1) if rss_start else None,
            rss_end_kb=round(rss_end / 1024.0, 1) if rss_end else None,
            rss_peak_kb=round(rss_peak / 1024.0, 1) if rss_peak else None,
            observation_rows=harness.observations.count(),
            session_rows=harness.sessions.count(),
            engine_persistence_entries=len(harness.pipeline.engine.persistence_counts),
            known_bssids=harness.pipeline.known_bssids_count,
        )


# ------------------------------------------------------------------- output


def _format_table(results: Sequence[TimingResult]) -> str:
    """Render timing results as a fixed-width text table."""
    headers = ("metric", "n", "min ms", "median ms", "p95 ms", "max ms", "rate", "notes")
    rows = [
        (
            result.name,
            str(result.count),
            f"{result.min_ms:,.3f}",
            f"{result.median_ms:,.3f}",
            f"{result.p95_ms:,.3f}",
            f"{result.max_ms:,.3f}",
            f"{result.per_second:,.0f}/s",
            result.notes,
        )
        for result in results
    ]
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows)) if rows else len(headers[column])
        for column in range(len(headers))
    ]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    separator = "  ".join("-" * width for width in widths)
    return "\n".join([line(headers), separator, *(line(row) for row in rows)])


def _format_memory(memory: MemoryResult) -> str:
    """Render the memory phase as aligned key/value lines."""
    rows: list[tuple[str, str]] = [
        ("simulated scans", str(memory.scans)),
        ("wall time", f"{memory.wall_seconds:,.2f} s ({memory.wall_seconds / max(memory.scans, 1) * 1000:,.1f} ms/scan)"),
        ("tracemalloc start", f"{memory.tracemalloc_start_kb:,.1f} KiB"),
        ("tracemalloc end (live)", f"{memory.tracemalloc_end_kb:,.1f} KiB"),
        ("tracemalloc peak", f"{memory.tracemalloc_peak_kb:,.1f} KiB"),
        ("tracemalloc growth", f"{memory.tracemalloc_end_kb - memory.tracemalloc_start_kb:,.1f} KiB"),
        ("RSS start", f"{_kb(memory.rss_start_kb)}"),
        ("RSS end", f"{_kb(memory.rss_end_kb)}"),
        ("RSS peak", f"{_kb(memory.rss_peak_kb)}"),
        (
            "RSS growth",
            f"{_kb(memory.rss_end_kb - memory.rss_start_kb) if memory.rss_start_kb is not None and memory.rss_end_kb is not None else 'n/a'}",
        ),
        ("observation rows written", str(memory.observation_rows)),
        ("scan sessions written", str(memory.session_rows)),
        ("engine persistence entries", str(memory.engine_persistence_entries)),
        ("distinct BSSIDs tracked", str(memory.known_bssids)),
    ]
    width = max(len(name) for name, _ in rows)
    return "\n".join(f"  {name.ljust(width)}  {value}" for name, value in rows)


def _kb(value: float | None) -> str:
    """Format a KiB value or the literal ``n/a``."""
    return "n/a" if value is None else f"{value:,.1f} KiB"


def _print_environment(env: EnvironmentInfo) -> None:
    """Print the machine/interpreter header."""
    print("Rogue AP Hunter - offline performance benchmark")
    print("=" * 78)
    print(f"  timestamp    : {env.timestamp}")
    print(f"  OS           : {env.os}")
    print(f"  machine      : {env.machine}")
    print(f"  CPU          : {env.cpu} ({env.logical_cpus} logical processors)")
    print(f"  RAM          : {env.total_ram_gb} GiB" if env.total_ram_gb else "  RAM          : n/a")
    print(f"  Python       : {env.python}")
    print(f"  repo root    : {REPO_ROOT}")
    print()


# ----------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Offline performance benchmark for Rogue AP Hunter (no radio, no GUI).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="timed iterations for the parser, pipeline, storage and alert phases",
    )
    parser.add_argument(
        "--scans",
        type=int,
        default=300,
        help="simulated scans for the prolonged-monitoring memory phase",
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=1000,
        help="rows per storage batch measurement",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        metavar="PATH",
        help="also write machine-readable results to this file",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run every benchmark phase and print the results; return an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    if args.scans < 1:
        parser.error("--scans must be >= 1")
    if args.batch < 1:
        parser.error("--batch must be >= 1")

    env = environment_info()
    networks_text = _fixture_text(NETWORKS_FIXTURE)

    timings: list[TimingResult] = []
    with TemporaryDirectory(prefix="rogue-ap-bench-") as temporary:
        workdir = Path(temporary)

        print(f"parser throughput ({args.iterations} parses)...")
        parser_result, observation_count = bench_parser(networks_text, args.iterations)
        timings.append(parser_result)

        print(f"end-to-end pipeline ({args.iterations} scans)...")
        timings.append(bench_pipeline(args.iterations, workdir / "pipeline.sqlite3"))

        print(f"storage writes ({args.iterations} singles, {BATCH_REPEATS} x {args.batch}-row batches)...")
        timings.extend(bench_db_writes(args.iterations, args.batch, workdir / "storage.sqlite3"))

        print(f"alert processing ({args.iterations} identities x 3 transitions)...")
        alert_timings, alert_stats = bench_alerts(args.iterations, workdir / "alerts.sqlite3")
        timings.extend(alert_timings)

        print(f"memory over {args.scans} simulated scans...")
        memory = bench_memory(args.scans, workdir / "memory.sqlite3")

    print()
    _print_environment(env)
    print(_format_table(timings))
    print()
    print(f"Alert transitions: {alert_stats.created} created, {alert_stats.escalated} escalated, "
          f"{alert_stats.deduplicated} deduplicated repeats; "
          f"{alert_stats.notifications_delivered} notification(s) delivered "
          f"(cooldown {alert_stats.min_notification_interval_seconds}s per identity)")
    print()
    print("Memory during prolonged monitoring:")
    print(_format_memory(memory))
    print()

    if args.json is not None:
        payload = {
            "environment": asdict(env),
            "parameters": {
                "iterations": args.iterations,
                "scans": args.scans,
                "batch": args.batch,
                "warmup_scans": WARMUP_SCANS,
                "batch_repeats": BATCH_REPEATS,
            },
            "fixtures": {
                "networks": NETWORKS_FIXTURE,
                "observations_per_parse": observation_count,
            },
            "metrics": [asdict(result) for result in timings],
            "alert_transitions": asdict(alert_stats),
            "memory": asdict(memory),
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"JSON results written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
