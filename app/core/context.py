"""Application context: the single wiring point for every subsystem.

The context builds configuration, storage, scanning, detection, scoring and
alerting once, and hands them to the interface layer. Keeping construction
here means tests can build the same object graph with temporary paths and
fake scanners, and the UI never instantiates repositories itself.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from app.alerts import AlertManager, CompositeNotifier, LogNotifier, Notifier, WindowsToastNotifier
from app.core import paths
from app.core.config import Config, ConfigError, load_config, save_config
from app.detection import DetectionEngine
from app.scanner import NetshScanner
from app.scoring import RiskScorer
from app.services import MonitoringService, ScanPipeline, ScanReport
from app.storage import (
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    SettingRepository,
    TrustedNetworkRepository,
)

logger = logging.getLogger(__name__)

__all__ = ["AppContext", "default_notifier"]


def default_notifier(*, desktop: bool = True) -> Notifier:
    """Build the standard notification chain: desktop toast, then log."""
    if desktop:
        return CompositeNotifier(WindowsToastNotifier(), LogNotifier())
    return LogNotifier()


class AppContext:
    """Owns the object graph for one application run.

    Parameters
    ----------
    config_path:
        Explicit configuration file; defaults to the per-user location.
    notifier:
        Notification channel; ``None`` builds the default chain.
    scanner:
        Scanner override (tests inject fakes here).
    """

    def __init__(
        self,
        *,
        config_path: Path | None = None,
        notifier: Notifier | None = None,
        scanner: NetshScanner | None = None,
        config: Config | None = None,
    ) -> None:
        self.config_path = config_path or paths.config_path()
        self.config = config or self._load_config()

        if config_path is None:
            paths.ensure_app_dirs()
            database_path = paths.database_path()
        else:
            database_path = config_path.parent / "data" / "rogue_ap_hunter.sqlite3"

        self.database = Database(database_path)
        self.database.open()

        self.observations = ObservationRepository(self.database)
        self.sessions = ScanSessionRepository(self.database)
        self.trusted = TrustedNetworkRepository(self.database)
        self.alerts = AlertRepository(self.database)
        self.scores = RiskScoreRepository(self.database)
        self.settings = SettingRepository(self.database)

        self.engine = DetectionEngine(self.config)
        self.scorer = RiskScorer(self.config)
        self.alert_manager = AlertManager(
            self.alerts,
            config=self.config,
            notifier=notifier if notifier is not None else default_notifier(),
        )

        self.scanner = scanner or NetshScanner()
        self.pipeline = ScanPipeline(
            scanner=self.scanner,
            observations=self.observations,
            sessions=self.sessions,
            trusted=self.trusted,
            scores=self.scores,
            alert_repository=self.alerts,
            alert_manager=self.alert_manager,
            config=self.config,
            engine=self.engine,
            scorer=self.scorer,
        )
        self.monitoring = MonitoringService(
            self.pipeline,
            interval_seconds=self.config.scan_interval_seconds,
        )
        logger.debug("application context built (config=%s, db=%s)", self.config_path, self.database.path)

    # ------------------------------------------------------------- lifecycle

    def _load_config(self) -> Config:
        try:
            return load_config(self.config_path)
        except ConfigError as exc:
            logger.error("configuration unusable (%s); using defaults", exc)
            return Config()

    def save_config(self, config: Config) -> Path:
        """Persist configuration and apply it to live services."""
        config.validate()
        saved = save_config(config, self.config_path)
        self.apply_config(config)
        return saved

    def apply_config(self, config: Config) -> None:
        """Re-point the running services at a new configuration."""
        previous = self.config
        self.config = config
        self.alert_manager = AlertManager(
            self.alerts,
            config=config,
            notifier=self.alert_manager.notifier,
            notify_below_severity=self.alert_manager.notify_below_severity,
        )
        # The pipeline keeps its own references: push the new configuration
        # into it, otherwise weights, thresholds and retention would keep the
        # values captured at construction time until the app restarts.
        self.pipeline.apply_config(config, alert_manager=self.alert_manager)
        self.engine = self.pipeline.engine
        self.scorer = self.pipeline.scorer

        if previous.scan_interval_seconds != config.scan_interval_seconds:
            logger.info(
                "scan interval changed from %ss to %ss",
                previous.scan_interval_seconds,
                config.scan_interval_seconds,
            )
            was_running = self.monitoring.is_running
            on_report = self.monitoring.on_report
            on_error = self.monitoring.on_error
            if was_running:
                self.monitoring.stop()
            self.monitoring = MonitoringService(
                self.pipeline,
                interval_seconds=config.scan_interval_seconds,
                on_report=on_report,
                on_error=on_error,
            )
            if was_running:
                self.monitoring.start()

    def set_callbacks(
        self,
        on_report: Callable[[ScanReport], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Attach UI callbacks to the monitoring loop."""
        self.monitoring.set_callbacks(on_report=on_report, on_error=on_error)

    def close(self) -> None:
        """Stop monitoring and release storage."""
        try:
            self.monitoring.stop(timeout=10)
        except Exception:  # pragma: no cover - defensive
            logger.exception("monitoring did not stop cleanly")
        try:
            self.database.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("database did not close cleanly")
        logger.debug("application context closed")

    def __enter__(self) -> AppContext:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
