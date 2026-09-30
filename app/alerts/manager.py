"""Alert lifecycle: creation, deduplication, acknowledgement and resolution.

The manager is the only place that decides when the user should be bothered:
notifications fire on meaningful transitions (a new alert, or an escalation in
severity) and never more often than a configurable interval per alert.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from app.alerts.notifiers import Notifier
from app.core.config import Config
from app.models import Alert, AlertStatus, Severity, utcnow
from app.storage import AlertRepository

logger = logging.getLogger(__name__)

__all__ = ["AlertManager", "AlertTransition"]

DEFAULT_MIN_NOTIFICATION_INTERVAL_SECONDS = 60


@dataclass(frozen=True, slots=True)
class AlertTransition:
    """What happened to an alert during :meth:`AlertManager.record`."""

    alert: Alert
    created: bool
    escalated: bool
    notified: bool
    previous_severity: Severity | None = None

    @property
    def is_meaningful(self) -> bool:
        """``True`` when this transition deserves the user's attention."""
        return self.created or self.escalated


class AlertManager:
    """Coordinates persistence and notification for alerts.

    Parameters
    ----------
    repository:
        Storage backing the alert list.
    config:
        Supplies severity thresholds for derived severities.
    notifier:
        Notification channel; ``None`` disables desktop notification while
        keeping full in-app behaviour.
    min_notification_interval:
        Seconds between notifications for the same alert identity.
    """

    def __init__(
        self,
        repository: AlertRepository,
        *,
        config: Config | None = None,
        notifier: Notifier | None = None,
        min_notification_interval: int = DEFAULT_MIN_NOTIFICATION_INTERVAL_SECONDS,
        notify_below_severity: Severity = Severity.SUSPICIOUS,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if min_notification_interval < 0:
            raise ValueError("min_notification_interval must be >= 0")
        self._repository = repository
        self._config = config or Config()
        self._notifier = notifier
        self._interval = min_notification_interval
        self._notify_below = notify_below_severity
        self._clock = clock
        self._last_notified: dict[tuple[str | None, str | None, str], datetime] = {}

    @property
    def notifier(self) -> Notifier | None:
        """Notification channel in use (``None`` disables desktop alerts)."""
        return self._notifier

    @property
    def notify_below_severity(self) -> Severity:
        """Lowest severity that triggers a desktop notification."""
        return self._notify_below

    @property
    def repository(self) -> AlertRepository:
        """Backing alert storage."""
        return self._repository

    @property
    def config(self) -> Config:
        """Configuration this manager was last pointed at."""
        return self._config

    def apply_config(self, config: Config) -> None:
        """Adopt a new configuration in place.

        Rebuilding the manager instead would silently discard the per-identity
        notification cooldown state and the configured interval.
        """
        self._config = config

    # ------------------------------------------------------------- recording

    def record(self, alert: Alert) -> AlertTransition:
        """Persist an alert occurrence and notify on meaningful transitions."""
        existing = self._repository.find_open_match(alert)

        if existing is None:
            stored = self._repository.add(alert)
            transition = AlertTransition(alert=stored, created=True, escalated=False, notified=False)
            transition = self._maybe_notify(transition)
            logger.info(
                "new alert %s for %s [%s] score=%d",
                stored.alert_type.value,
                stored.ssid or "<hidden>",
                stored.bssid or "unknown",
                stored.risk_score,
            )
            return transition

        stored = self._repository.record_occurrence(existing, alert)
        previous_rank = existing.severity.rank if existing.severity else Severity.LOW.rank
        new_rank = stored.severity.rank if stored.severity else Severity.LOW.rank
        escalated = new_rank > previous_rank

        transition = AlertTransition(
            alert=stored,
            created=False,
            escalated=escalated,
            notified=False,
            previous_severity=existing.severity,
        )
        if escalated:
            logger.warning(
                "alert escalated to %s for %s [%s] score=%d",
                stored.severity.value if stored.severity else "?",
                stored.ssid or "<hidden>",
                stored.bssid or "unknown",
                stored.risk_score,
            )
            transition = self._maybe_notify(transition)
        return transition

    def record_many(self, alerts: list[Alert]) -> list[AlertTransition]:
        """Record several alerts, returning their transitions in order."""
        return [self.record(alert) for alert in alerts]

    # --------------------------------------------------------------- workflow

    def acknowledge(self, alert_id: int) -> Alert | None:
        """Mark an alert as acknowledged."""
        updated = self._repository.set_status(alert_id, AlertStatus.ACKNOWLEDGED)
        if updated is None:
            logger.warning("acknowledge requested for missing alert id=%s", alert_id)
        return updated

    def resolve(self, alert_id: int) -> Alert | None:
        """Mark an alert as resolved."""
        updated = self._repository.set_status(alert_id, AlertStatus.RESOLVED)
        if updated is None:
            logger.warning("resolve requested for missing alert id=%s", alert_id)
        return updated

    def reopen(self, alert_id: int) -> Alert | None:
        """Return an alert to the active list."""
        return self._repository.set_status(alert_id, AlertStatus.ACTIVE)

    # ----------------------------------------------------------------- queries

    def active(self, *, severity: Severity | None = None, limit: int = 200) -> list[Alert]:
        """Open alerts, optionally filtered by severity."""
        return self._repository.list(status=AlertStatus.ACTIVE, severity=severity, limit=limit)

    def history(self, **filters: object) -> list[Alert]:
        """Full history with optional repository filters."""
        return self._repository.list(**filters)  # type: ignore[arg-type]

    def counts(self) -> dict[str, int]:
        """Open alert counts keyed by severity."""
        return self._repository.counts_by_severity()

    # ------------------------------------------------------------- notification

    def _maybe_notify(self, transition: AlertTransition) -> AlertTransition:
        """Send a notification when the transition is meaningful and due."""
        if self._notifier is None or not transition.is_meaningful:
            return transition

        alert = transition.alert
        if alert.severity is not None and alert.severity.rank < self._notify_below.rank:
            return transition

        key = (alert.ssid, alert.bssid, alert.alert_type.value)
        now = self._clock()
        last = self._last_notified.get(key)
        if last is not None and (now - last).total_seconds() < self._interval:
            logger.debug("notification suppressed for %s (interval)", key)
            return transition

        try:
            delivered = bool(self._notifier.notify(alert))
        except Exception:  # pragma: no cover - notifier bugs must not break monitoring
            logger.exception("notifier raised; notification considered failed")
            delivered = False

        if delivered:
            self._last_notified[key] = now
        return AlertTransition(
            alert=transition.alert,
            created=transition.created,
            escalated=transition.escalated,
            notified=delivered,
            previous_severity=transition.previous_severity,
        )
