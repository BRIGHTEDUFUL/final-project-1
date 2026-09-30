"""Monitoring: the periodic scan loop and the end-to-end scan pipeline.

The pipeline is deliberately synchronous and side-effect-complete: one call
runs scan -> parse -> detect -> score -> persist -> alert. The service wraps
it in a background thread with a start/stop lifecycle that never overlaps
scans and never lets an exception escape into the void.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from time import perf_counter

from app.alerts import AlertManager, AlertTransition
from app.capture import FrameObserver
from app.core.config import Config
from app.detection import DetectionContext, DetectionEngine, Finding
from app.models import Alert, AlertType, NetworkObservation, ScanSession, ScanSessionStatus, utcnow
from app.parser import InterfaceInfo, parse_interfaces, parse_visible_networks_as_observations
from app.scanner import NetshScanner, ScannerError
from app.scoring import RiskAssessment, RiskScorer
from app.storage import (
    AlertRepository,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    TrustedNetworkRepository,
)

logger = logging.getLogger(__name__)

__all__ = ["MonitoringService", "ScanPipeline", "ScanReport"]

DEFAULT_PRUNE_EVERY_SCANS = 20


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Everything one monitoring pass produced."""

    session: ScanSession
    observations: tuple[NetworkObservation, ...] = ()
    findings: tuple[Finding, ...] = ()
    assessments: tuple[RiskAssessment, ...] = ()
    alerts: tuple[AlertTransition, ...] = ()
    duration_seconds: float = 0.0
    error: str | None = None
    scanner_detail: str = ""

    @property
    def ok(self) -> bool:
        """``True`` when the scan completed without error."""
        return self.error is None

    @property
    def network_count(self) -> int:
        """Number of radio observations captured."""
        return len(self.observations)

    @property
    def has_findings(self) -> bool:
        """``True`` when at least one indicator matched."""
        return bool(self.findings)

    @property
    def new_alerts(self) -> tuple[AlertTransition, ...]:
        """Transitions that created a brand-new alert."""
        return tuple(t for t in self.alerts if t.created)

    def summary(self) -> str:
        """One-line status for logs and the dashboard."""
        if not self.ok:
            return f"scan failed: {self.error}"
        return (
            f"{self.network_count} networks, {len(self.findings)} findings, "
            f"{len(self.new_alerts)} new alerts in {self.duration_seconds:.2f}s"
        )


def _alert_type_for(assessment: RiskAssessment) -> AlertType:
    """Pick the dominant indicator so alerts group by their strongest reason."""
    if not assessment.findings:
        return AlertType.OTHER
    top = max(assessment.findings, key=lambda f: (f.weight, f.rule.value))
    try:
        return AlertType(top.rule.value)
    except ValueError:  # pragma: no cover - values are kept in sync by design
        return AlertType.OTHER


class ScanPipeline:
    """Executes one complete scan-and-evaluate pass."""

    def __init__(
        self,
        *,
        scanner: NetshScanner,
        observations: ObservationRepository,
        sessions: ScanSessionRepository,
        trusted: TrustedNetworkRepository,
        scores: RiskScoreRepository,
        alert_manager: AlertManager,
        alert_repository: AlertRepository,
        config: Config | None = None,
        engine: DetectionEngine | None = None,
        scorer: RiskScorer | None = None,
        frame_observer: FrameObserver | None = None,
        prune_every: int = DEFAULT_PRUNE_EVERY_SCANS,
    ) -> None:
        self._scanner = scanner
        self._observations = observations
        self._sessions = sessions
        self._trusted = trusted
        self._scores = scores
        self._alerts = alert_repository
        self._alert_manager = alert_manager
        self._config = config or Config()
        self._engine = engine or DetectionEngine(self._config)
        self._scorer = scorer or RiskScorer(self._config)
        self._frame_observer = frame_observer
        self._prune_every = max(1, prune_every)
        self._known_bssids: frozenset[str] | None = None
        self._scan_counter = 0
        self.last_interface: InterfaceInfo | None = None
        self.last_error: str | None = None

    @property
    def engine(self) -> DetectionEngine:
        """Detection engine in use (shared state survives across scans)."""
        return self._engine

    @property
    def scorer(self) -> RiskScorer:
        """Risk scorer in use."""
        return self._scorer

    @property
    def config(self) -> Config:
        """Configuration currently driving detection, scoring and retention."""
        return self._config

    def apply_config(
        self,
        config: Config,
        *,
        alert_manager: AlertManager | None = None,
    ) -> None:
        """Re-point the running pipeline at a new configuration.

        Weights, thresholds and the retention window take effect on the next
        scan. The engine keeps its learned persistence counters so a settings
        change never erases what monitoring has already observed.
        """
        self._config = config
        self._engine = self._engine.with_config(config)
        self._scorer = RiskScorer(config)
        if alert_manager is not None:
            self._alert_manager = alert_manager

    @property
    def known_bssids_count(self) -> int:
        """Size of the loaded BSSID history."""
        return len(self.known_bssids)

    @property
    def known_bssids(self) -> frozenset[str]:
        """Cached BSSID history; loaded from storage on first use."""
        if self._known_bssids is None:
            try:
                self._known_bssids = self._observations.known_bssids()
            except Exception:
                logger.exception("could not load BSSID history; starting empty")
                self._known_bssids = frozenset()
        return self._known_bssids

    def run(self) -> ScanReport:
        """Run one full pass. Never raises: failures become error reports."""
        started = perf_counter()
        try:
            session = self._sessions.start()
        except Exception:
            # Storage is unusable (locked, read-only, deleted mid-run): there is
            # no session row to update, so report the failure in memory only.
            logger.exception("could not open a scan session; storage unavailable")
            session = ScanSession().finish(ScanSessionStatus.FAILED)
            report = ScanReport(
                session=session,
                duration_seconds=perf_counter() - started,
                error="could not open a scan session; local storage is unavailable",
            )
            self.last_error = report.error
            logger.info("%s", report.summary())
            return report
        try:
            report = self._execute(session, started)
        except ScannerError as exc:
            logger.warning("scanner failure: %s", exc)
            report = self._fail(session, started, str(exc))
        except Exception as exc:
            logger.exception("unexpected scan failure")
            report = self._fail(session, started, f"unexpected error: {exc}")
        self.last_error = None if report.ok else report.error
        logger.info("%s", report.summary())
        return report

    # ------------------------------------------------------------- internals

    def _fail(self, session: ScanSession, started: float, error: str) -> ScanReport:
        try:
            session = self._sessions.finish(session, status=ScanSessionStatus.FAILED)
        except Exception:
            logger.exception("could not persist failed session")
            # Keep the in-memory report truthful even when storage is down.
            session = session.finish(ScanSessionStatus.FAILED)
        return ScanReport(
            session=session,
            duration_seconds=perf_counter() - started,
            error=error,
        )

    def _execute(self, session: ScanSession, started: float) -> ScanReport:
        usable, detail = self._scanner.available()
        if not usable:
            return self._fail(session, started, f"wireless scanning unavailable: {detail}")

        result = self._scanner.scan()
        if not result.ok:
            return self._fail(session, started, result.summary())

        observations = parse_visible_networks_as_observations(result.stdout, observed_at=utcnow())
        connected_bssid, connected_signal = self._connection_state()

        known = self.known_bssids
        context = DetectionContext(
            observations=tuple(observations),
            trusted=tuple(self._trusted.list()),
            known_bssids=known,
            connected_bssid=connected_bssid,
            connected_signal=connected_signal,
            history_available=bool(known),
        )

        detection = self._engine.evaluate(context)
        assessments = tuple(self._scorer.assess_grouped(detection.groups))

        # Persist first: history must exist for the next scan's comparison.
        self._observations.add_many(observations, session_id=session.id)
        self._known_bssids = frozenset(
            {*(known), *(o.bssid for o in observations if o.bssid is not None)}
        )

        transitions: list[AlertTransition] = []
        for assessment in assessments:
            if assessment.score <= 0:
                continue
            # Evidence may be enriched with observed beacon facts; the score
            # itself stays the pure product of the configured risk weights.
            reasons = self._enriched_reasons(assessment.bssid, assessment.reasons)
            self._scores.add(
                ssid=assessment.ssid,
                bssid=assessment.bssid,
                score=assessment.score,
                severity=assessment.severity,
                reasons=reasons,
                created_at=assessment.evaluated_at,
            )
            alert = Alert.from_score(
                ssid=assessment.ssid,
                bssid=assessment.bssid,
                alert_type=_alert_type_for(assessment),
                risk_score=assessment.score,
                reasons=reasons,
                thresholds=self._scorer.thresholds(),
                created_at=assessment.evaluated_at,
            )
            transitions.append(self._alert_manager.record(alert))

        self._maybe_prune()

        session = self._sessions.finish(session, network_count=len(observations))
        return ScanReport(
            session=session,
            observations=tuple(observations),
            findings=tuple(detection.findings),
            assessments=assessments,
            alerts=tuple(transitions),
            duration_seconds=perf_counter() - started,
            scanner_detail=detail,
        )

    def _connection_state(self) -> tuple[str | None, int | None]:
        """Best-effort lookup of the adapter's own connection."""
        self.last_interface = None
        try:
            result = self._scanner.show_interfaces()
            if not result.ok:
                return None, None
            interfaces = parse_interfaces(result.stdout)
        except ScannerError:
            return None, None
        for info in interfaces:
            if info.is_connected and info.bssid:
                self.last_interface = info
                return info.bssid, info.signal
        if interfaces:
            self.last_interface = interfaces[0]
        return None, None

    def _enriched_reasons(self, bssid: str | None, reasons: tuple[str, ...]) -> tuple[str, ...]:
        """Append beacon-derived evidence lines without touching the score."""
        if self._frame_observer is None or bssid is None:
            return reasons
        extra = self._frame_observer.enrich(bssid)
        if not extra:
            return reasons
        return tuple(dict.fromkeys([*reasons, *extra]))

    def _maybe_prune(self) -> None:
        """Apply the retention window periodically, not on every scan."""
        self._scan_counter += 1
        if self._scan_counter % self._prune_every != 0:
            return
        cutoff = utcnow() - timedelta(days=self._config.data_retention_days)
        try:
            removed_obs = self._observations.prune(cutoff)
            removed_alerts = self._alerts.prune(cutoff)
            removed_scores = self._scores.prune(cutoff)
        except Exception:  # pragma: no cover - defensive
            logger.exception("retention pruning failed")
            return
        if removed_obs or removed_alerts or removed_scores:
            logger.info(
                "retention prune removed %d observations, %d alerts, %d scores",
                removed_obs,
                removed_alerts,
                removed_scores,
            )


class MonitoringService:
    """Background loop around a :class:`ScanPipeline`.

    Callbacks run on the worker thread: GUI callers must marshal to the UI
    thread themselves (for example with a Qt signal).
    """

    def __init__(
        self,
        pipeline: ScanPipeline,
        *,
        interval_seconds: int = 15,
        on_report: Callable[[ScanReport], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        thread_name: str = "rogue-ap-monitor",
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError(f"interval_seconds must be positive, got {interval_seconds}")
        self._pipeline = pipeline
        self._interval = interval_seconds
        self._on_report = on_report
        self._on_error = on_error
        self._thread_name = thread_name

        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._oneshot: threading.Thread | None = None
        self._last_report: ScanReport | None = None

    # -------------------------------------------------------------- state

    @property
    def is_running(self) -> bool:
        """``True`` while the background loop is active."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_report(self) -> ScanReport | None:
        """Most recent scan report, if any."""
        return self._last_report

    @property
    def interval_seconds(self) -> int:
        """Configured delay between scans."""
        return self._interval

    @property
    def on_report(self) -> Callable[[ScanReport], None] | None:
        """Current report callback."""
        return self._on_report

    @property
    def on_error(self) -> Callable[[str], None] | None:
        """Current error callback."""
        return self._on_error

    def set_callbacks(
        self,
        *,
        on_report: Callable[[ScanReport], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Replace the callbacks (safe while the loop is running)."""
        self._on_report = on_report
        self._on_error = on_error

    @property
    def pipeline(self) -> ScanPipeline:
        """The pipeline this service drives."""
        return self._pipeline

    # -------------------------------------------------------------- control

    def start(self) -> bool:
        """Start monitoring; returns ``False`` if it is already running."""
        with self._lifecycle_lock:
            if self.is_running:
                logger.warning("monitoring already running; start() ignored")
                return False
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name=self._thread_name,
                daemon=True,
            )
            self._thread.start()
        logger.info("monitoring started (interval %ss)", self._interval)
        return True

    def stop(self, timeout: float = 10.0) -> bool:
        """Stop monitoring and wait for the worker; ``False`` if not running."""
        with self._lifecycle_lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._stop_event.set()
                self._thread = None
                return False
            self._stop_event.set()
        thread.join(timeout=timeout)
        stopped = not thread.is_alive()
        with self._lifecycle_lock:
            self._thread = None if stopped else self._thread
        if stopped:
            logger.info("monitoring stopped")
        else:
            logger.warning("monitoring thread did not stop within %.1fs", timeout)
        return stopped

    def scan_once(self) -> ScanReport:
        """Run a single pass immediately (also used by tests and the UI)."""
        report = self._pipeline.run()
        self._last_report = report
        self._emit(report)
        return report

    def scan_once_async(self) -> bool:
        """Queue one scan on a background thread; ``False`` when busy.

        Never blocks the caller: the GUI hands the work over and re-enables
        its controls when the report arrives through the callbacks. A scan
        already in flight (the monitoring loop or a previous one-shot) makes
        this return ``False`` instead of queueing a duplicate pass.
        """
        with self._lifecycle_lock:
            worker = self._oneshot
            if worker is not None and worker.is_alive():
                return False
            if self._scan_lock.locked():
                return False
            worker = threading.Thread(
                target=self._oneshot_run,
                name="rogue-ap-oneshot",
                daemon=True,
            )
            self._oneshot = worker
        worker.start()
        logger.debug("one-shot scan queued")
        return True

    # -------------------------------------------------------------- internals

    def _oneshot_run(self) -> None:
        """Worker body for :meth:`scan_once_async`; never raises."""
        try:
            # Serialised with the monitoring loop's pass, so scans never
            # overlap. The lock is always released, even on failure.
            with self._scan_lock:
                self.scan_once()
        except Exception:  # pragma: no cover - defensive
            logger.exception("one-shot scan failed unexpectedly")

    def _loop(self) -> None:
        # Scan immediately on start so the dashboard is not empty for a cycle.
        while not self._stop_event.is_set():
            if self._scan_lock.acquire(blocking=False):
                try:
                    self.scan_once()
                except Exception:  # pragma: no cover - defensive
                    logger.exception("scan raised unexpectedly")
                finally:
                    self._scan_lock.release()
            self._stop_event.wait(self._interval)

    def _emit(self, report: ScanReport) -> None:
        if not report.ok and self._on_error is not None:
            try:
                self._on_error(report.error or "unknown error")
            except Exception:  # pragma: no cover - callbacks must not kill the loop
                logger.exception("on_error callback failed")
        if self._on_report is not None:
            try:
                self._on_report(report)
            except Exception:  # pragma: no cover - callbacks must not kill the loop
                logger.exception("on_report callback failed")
