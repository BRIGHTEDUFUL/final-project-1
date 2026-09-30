"""Unit tests for the alert manager and notification adapters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.alerts import (
    AlertManager,
    AlertTransition,
    CompositeNotifier,
    LogNotifier,
    NullNotifier,
    WindowsToastNotifier,
)
from app.models import Alert, AlertStatus, AlertType, Severity
from app.storage import AlertRepository, Database


class RecordingNotifier:
    """Counts notifications and can be told to fail or raise."""

    def __init__(self, *, fail: bool = False, raise_error: bool = False) -> None:
        self.fail = fail
        self.raise_error = raise_error
        self.alerts: list[Alert] = []

    def notify(self, alert: Alert) -> bool:
        if self.raise_error:
            raise RuntimeError("notifier exploded")
        self.alerts.append(alert)
        return not self.fail


@pytest.fixture
def repository(tmp_path) -> AlertRepository:
    db = Database(tmp_path / "alerts.sqlite3")
    db.open()
    yield AlertRepository(db)  # type: ignore[misc]
    db.close()


def alert(score: int = 45, *, ssid: str = "Evil", bssid: str = "de:ad:be:ef:00:01") -> Alert:
    return Alert.from_score(
        ssid=ssid,
        bssid=bssid,
        alert_type=AlertType.DUPLICATE_SSID,
        risk_score=score,
        reasons=("duplicate ssid observed",),
        created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )


# ----------------------------------------------------------------- recording


def test_first_record_creates_and_notifies(repository: AlertRepository) -> None:
    notifier = RecordingNotifier()
    manager = AlertManager(repository, notifier=notifier)

    transition = manager.record(alert(45))

    assert transition.created
    assert not transition.escalated
    assert transition.notified
    assert transition.is_meaningful
    assert len(notifier.alerts) == 1
    assert repository.count() == 1


def test_repeat_occurrence_deduplicates(repository: AlertRepository) -> None:
    notifier = RecordingNotifier()
    manager = AlertManager(repository, notifier=notifier)

    first = manager.record(alert(45))
    second = manager.record(alert(45))

    assert first.created
    assert not second.created
    assert not second.is_meaningful
    assert repository.count() == 1
    stored = repository.get(first.alert.id)  # type: ignore[arg-type]
    assert stored is not None and stored.occurrence_count == 2


def test_escalation_notifies_again(repository: AlertRepository) -> None:
    notifier = RecordingNotifier()
    manager = AlertManager(repository, notifier=notifier, min_notification_interval=0)

    manager.record(alert(45))
    escalation = manager.record(alert(90))

    assert escalation.escalated
    assert escalation.notified
    assert escalation.previous_severity is Severity.SUSPICIOUS
    assert escalation.alert.severity is Severity.CRITICAL
    assert len(notifier.alerts) == 2


def test_notification_interval_prevents_spam(repository: AlertRepository) -> None:
    now = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    notifier = RecordingNotifier()
    manager = AlertManager(
        repository,
        notifier=notifier,
        min_notification_interval=300,
        clock=lambda: now,
    )

    manager.record(alert(45))  # first sighting -> notify
    escalation = manager.record(alert(60))  # escalation inside the interval -> suppressed
    assert escalation.escalated
    assert not escalation.notified
    assert len(notifier.alerts) == 1

    # A later escalation (after the interval) notifies again.
    later = AlertManager(
        repository,
        notifier=notifier,
        min_notification_interval=0,
        clock=lambda: now + timedelta(seconds=600),
    )
    late = later.record(alert(90))
    assert late.escalated
    assert late.notified
    assert len(notifier.alerts) == 2


def test_low_severity_can_be_silenced(repository: AlertRepository) -> None:
    notifier = RecordingNotifier()
    manager = AlertManager(repository, notifier=notifier, notify_below_severity=Severity.HIGH)
    transition = manager.record(alert(10))  # low
    assert transition.created
    assert not transition.notified
    assert not notifier.alerts


def test_failing_notifier_never_breaks_recording(repository: AlertRepository) -> None:
    manager = AlertManager(repository, notifier=RecordingNotifier(fail=True))
    transition = manager.record(alert(45))
    assert transition.created
    assert not transition.notified
    assert repository.count() == 1

    exploding = AlertManager(repository, notifier=RecordingNotifier(raise_error=True))
    transition = exploding.record(alert(90, ssid="Other"))
    assert transition.created
    assert not transition.notified


def test_no_notifier_still_records(repository: AlertRepository) -> None:
    manager = AlertManager(repository)
    transition = manager.record(alert(45))
    assert transition.created
    assert not transition.notified


# ----------------------------------------------------------------- workflow


def test_acknowledge_resolve_and_reopen(repository: AlertRepository) -> None:
    manager = AlertManager(repository)
    created = manager.record(alert(45)).alert

    acked = manager.acknowledge(created.id)  # type: ignore[arg-type]
    assert acked is not None and acked.status is AlertStatus.ACKNOWLEDGED
    assert manager.active() == []

    resolved = manager.resolve(created.id)  # type: ignore[arg-type]
    assert resolved is not None and resolved.status is AlertStatus.RESOLVED

    reopened = manager.reopen(created.id)  # type: ignore[arg-type]
    assert reopened is not None and reopened.status is AlertStatus.ACTIVE
    assert len(manager.active()) == 1


def test_workflow_on_missing_alert_returns_none(repository: AlertRepository) -> None:
    manager = AlertManager(repository)
    assert manager.acknowledge(999) is None
    assert manager.resolve(999) is None
    assert manager.reopen(999) is None


def test_counts_and_history_filters(repository: AlertRepository) -> None:
    manager = AlertManager(repository)
    manager.record(alert(10, ssid="LowOne"))
    manager.record(alert(95, ssid="CriticalOne"))

    counts = manager.counts()
    assert counts == {"low": 1, "critical": 1}
    assert len(manager.history(severity=Severity.CRITICAL)) == 1
    assert len(manager.history(ssid="LowOne")) == 1


def test_invalid_interval_is_rejected(repository: AlertRepository) -> None:
    with pytest.raises(ValueError):
        AlertManager(repository, min_notification_interval=-1)


def test_transition_is_meaningful_property() -> None:
    alert_value = alert(45)
    fresh = AlertTransition(alert=alert_value, created=True, escalated=False, notified=True)
    repeat = AlertTransition(alert=alert_value, created=False, escalated=False, notified=False)
    assert fresh.is_meaningful
    assert not repeat.is_meaningful


# ---------------------------------------------------------------- notifiers


def test_null_and_log_notifiers_succeed() -> None:
    target = alert(45)
    assert NullNotifier().notify(target) is True
    assert LogNotifier().notify(target) is True


def test_composite_stops_at_first_success() -> None:
    failing = RecordingNotifier(fail=True)
    succeeding = RecordingNotifier()
    composite = CompositeNotifier(failing, succeeding)
    assert composite.notify(alert(45)) is True
    assert len(failing.alerts) == 1
    assert len(succeeding.alerts) == 1


def test_composite_reports_failure_when_all_fail() -> None:
    composite = CompositeNotifier(RecordingNotifier(fail=True), RecordingNotifier(fail=True))
    assert composite.notify(alert(45)) is False


def test_composite_survives_raising_notifier() -> None:
    composite = CompositeNotifier(RecordingNotifier(raise_error=True), RecordingNotifier())
    assert composite.notify(alert(45)) is True


def test_toast_notifier_reports_availability() -> None:
    notifier = WindowsToastNotifier()
    assert isinstance(notifier.available, bool)


def test_toast_notifier_uses_injected_runner() -> None:
    captured: dict = {}

    def runner(arguments, timeout, environment):
        captured["arguments"] = arguments
        captured["timeout"] = timeout
        captured["environment"] = environment

        class Result:
            returncode = 0

        return Result()

    notifier = WindowsToastNotifier(runner=runner)
    assert notifier.notify(alert(45)) is True
    assert "-NoProfile" in captured["arguments"]
    assert captured["environment"]["RAPH_TITLE"]
    assert "Evil" in captured["environment"]["RAPH_MESSAGE"]


def test_toast_notifier_handles_failure_and_errors() -> None:
    def failing_runner(*_args, **_kwargs):
        class Result:
            returncode = 1
            stderr = b"boom"

        return Result()

    assert WindowsToastNotifier(runner=failing_runner).notify(alert(45)) is False

    def raising_runner(*_args, **_kwargs):
        raise OSError("cannot start powershell")

    assert WindowsToastNotifier(runner=raising_runner).notify(alert(45)) is False
