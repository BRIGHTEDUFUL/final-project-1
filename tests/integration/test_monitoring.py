"""Integration tests: scan -> parse -> detect -> score -> persist -> alert."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from app.alerts import AlertManager, NullNotifier
from app.core.config import Config
from app.models import AlertStatus, ScanSessionStatus, Severity, TrustedNetwork
from app.services import MonitoringService, ScanPipeline, ScanReport
from app.storage import (
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    TrustedNetworkRepository,
)
from tests.support import FakeScanner

NETWORKS_FIXTURE = "netsh_show_networks_multi.txt"
INTERFACES_FIXTURE = "netsh_show_interfaces_connected.txt"


@pytest.fixture
def env(tmp_path: Path, load_fixture):
    database = Database(tmp_path / "monitor.sqlite3")
    database.open()
    observations = ObservationRepository(database)
    sessions = ScanSessionRepository(database)
    trusted = TrustedNetworkRepository(database)
    alerts = AlertRepository(database)
    scores = RiskScoreRepository(database)
    manager = AlertManager(alerts, config=Config(), notifier=NullNotifier())
    scanner = FakeScanner(
        network_text=load_fixture(NETWORKS_FIXTURE),
        interface_text=load_fixture(INTERFACES_FIXTURE),
    )
    config = Config()
    pipeline = ScanPipeline(
        scanner=scanner,  # type: ignore[arg-type]
        observations=observations,
        sessions=sessions,
        trusted=trusted,
        scores=scores,
        alert_repository=alerts,
        alert_manager=manager,
        config=config,
        prune_every=1,
    )
    yield {
        "database": database,
        "observations": observations,
        "sessions": sessions,
        "trusted": trusted,
        "alerts": alerts,
        "scores": scores,
        "manager": manager,
        "scanner": scanner,
        "pipeline": pipeline,
        "config": config,
        "load_fixture": load_fixture,
    }
    database.close()


# ------------------------------------------------------------------- pipeline


def test_first_scan_records_everything(env) -> None:
    report = env["pipeline"].run()

    assert report.ok, report.error
    assert report.network_count == 4  # fixture has 4 radios
    assert report.session.status is ScanSessionStatus.COMPLETED
    assert env["observations"].count() == 4
    assert env["sessions"].count() == 1
    assert report.duration_seconds >= 0
    # No history yet -> the new-access-point rule stays quiet on scan one,
    # but the shared SSID and the near-maximum signal still raise findings.
    assert report.has_findings
    rules = {f.rule.value for f in report.findings}
    assert rules <= {"duplicate_ssid", "suspicious_signal"}
    assert "new_access_point" not in rules
    assert env["alerts"].count() == len(report.assessments) == 3


def test_second_scan_knows_the_environment(env) -> None:
    env["pipeline"].run()
    report = env["pipeline"].run()

    assert report.ok
    new_ap = [f for f in report.findings if f.rule.value == "new_access_point"]
    assert new_ap == [], "every BSSID was recorded on scan one, nothing is new"
    # Alert deduplication: the same identities must not create new rows.
    assert env["alerts"].count() == 3
    assert all(a.occurrence_count >= 1 for a in env["alerts"].list())


def test_security_downgrade_creates_an_alert(env) -> None:
    env["trusted"].upsert(
        TrustedNetwork(
            ssid="Corporate",
            approved_bssids=("10:20:30:40:50:60", "10:20:30:40:50:61"),
            expected_security="WPA3-SAE",
        )
    )
    report = env["pipeline"].run()

    assert report.has_findings
    downgrades = [f for f in report.findings if f.rule.value == "security_downgrade"]
    assert len(downgrades) == 2  # both radios report WPA2-Enterprise

    assert len(report.new_alerts) >= 1
    stored = env["alerts"].list()
    downgrade_alerts = [a for a in stored if a.alert_type.value == "security_downgrade"]
    assert len(downgrade_alerts) == 2
    assert all(a.risk_score >= 30 for a in downgrade_alerts)
    assert all(a.reasons for a in downgrade_alerts)


def test_duplicate_ssid_and_unknown_bssid_are_scored(env) -> None:
    env["trusted"].upsert(
        TrustedNetwork(ssid="Corporate", approved_bssids=("10:20:30:40:50:60",)),
    )
    report = env["pipeline"].run()

    rules = {f.rule.value for f in report.findings}
    assert "duplicate_ssid" in rules
    assert "unknown_bssid" in rules
    assert report.assessments
    worst = max(report.assessments, key=lambda a: a.score)
    assert worst.score >= 45  # 25 duplicate + 20 unknown
    assert worst.severity in {Severity.SUSPICIOUS, Severity.HIGH, Severity.CRITICAL}
    # Score history is persisted for the investigation view.
    history = env["scores"].history(ssid=worst.ssid, bssid=worst.bssid)
    assert history and history[0]["score"] == worst.score


def test_unavailable_wireless_returns_error_report(env) -> None:
    env["scanner"].usable = (False, "no wireless interfaces are present on this system")
    report = env["pipeline"].run()

    assert not report.ok
    assert "no wireless interfaces" in (report.error or "")
    assert report.network_count == 0
    sessions = env["sessions"].recent()
    assert sessions[0].status is ScanSessionStatus.FAILED


def test_failed_scan_command_returns_error_report(env) -> None:
    env["scanner"].scan_ok = False
    report = env["pipeline"].run()
    assert not report.ok
    assert env["sessions"].recent()[0].status is ScanSessionStatus.FAILED


def test_empty_scan_is_a_valid_report(env, load_fixture) -> None:
    env["scanner"].network_text = load_fixture("netsh_show_networks_empty.txt")
    report = env["pipeline"].run()
    assert report.ok
    assert report.network_count == 0
    assert report.has_findings is False


def test_prune_removes_old_data(env) -> None:
    from datetime import UTC, datetime, timedelta

    from app.models import NetworkObservation

    env["pipeline"].run()
    env["observations"].add(
        NetworkObservation(
            ssid="Old",
            bssid="01:02:03:04:05:06",
            observed_at=datetime.now(UTC) - timedelta(days=400),
        )
    )
    env["pipeline"].run()  # prune_every=1 applies the 90-day retention window
    ssids = {o.ssid for o in env["observations"].recent(limit=100)}
    assert "Old" not in ssids


# --------------------------------------------------------------------- service


def test_service_start_scan_stop(env) -> None:
    reports: list = []
    service = MonitoringService(env["pipeline"], interval_seconds=1, on_report=reports.append)

    assert not service.is_running
    assert service.start() is True
    assert service.start() is False  # double start is refused

    deadline = threading.Event()
    for _ in range(50):
        if service.last_report is not None:
            break
        deadline.wait(0.1)
    assert service.last_report is not None

    assert service.stop(timeout=5) is True
    assert not service.is_running
    assert reports, "callback should have been invoked for at least one scan"


def test_service_stop_without_start_returns_false(env) -> None:
    service = MonitoringService(env["pipeline"], interval_seconds=1)
    assert service.stop() is False


def test_service_rejects_invalid_interval(env) -> None:
    with pytest.raises(ValueError):
        MonitoringService(env["pipeline"], interval_seconds=0)


def test_callback_failures_do_not_kill_the_service(env) -> None:
    def exploding(_report) -> None:
        raise RuntimeError("callback blew up")

    def exploding_error(_message: str) -> None:
        raise RuntimeError("error callback blew up")

    service = MonitoringService(
        env["pipeline"],
        interval_seconds=1,
        on_report=exploding,
        on_error=exploding_error,
    )
    assert service.start()
    for _ in range(50):
        if service.last_report is not None:
            break
        threading.Event().wait(0.1)
    assert service.last_report is not None
    assert service.stop(timeout=5)


def test_scan_once_reports_errors_without_raising(env) -> None:
    env["scanner"].usable = (False, "wlansvc not running")
    service = MonitoringService(env["pipeline"], interval_seconds=1)
    report = service.scan_once()
    assert not report.ok
    assert service.last_report is report
    assert "failed" in report.summary()


def test_scan_once_async_runs_off_the_calling_thread(env) -> None:
    env["scanner"].delay = 0.1
    done = threading.Event()
    reports: list[ScanReport] = []

    def _collect(report: ScanReport) -> None:
        reports.append(report)
        done.set()

    service = MonitoringService(env["pipeline"], interval_seconds=3600, on_report=_collect)

    assert service.scan_once_async() is True, "submission must succeed when idle"
    assert service.last_report is None, "the caller must not block on the scan"
    assert done.wait(10), "the queued scan must run and report"
    worker = service._oneshot  # noqa: SLF001
    if worker is not None:
        worker.join(5)

    assert len(reports) == 1
    assert reports[0].ok
    assert service.scan_once_async() is True, "a finished one-shot frees the slot"


def test_scan_once_async_refuses_overlapping_submissions(env) -> None:
    env["scanner"].delay = 0.2
    done = threading.Event()
    service = MonitoringService(
        env["pipeline"], interval_seconds=3600, on_report=lambda _report: done.set()
    )

    assert service.scan_once_async() is True
    assert service.scan_once_async() is False, "a second submission must be refused while busy"
    assert done.wait(10), "the queued scan must still run"
    worker = service._oneshot  # noqa: SLF001
    if worker is not None:
        worker.join(5)

    done.clear()
    assert service.scan_once_async() is True, "the slot frees once the worker exits"
    assert done.wait(10)


def test_scan_once_async_refuses_while_the_loop_is_scanning(env) -> None:
    service = MonitoringService(env["pipeline"], interval_seconds=3600)
    assert service._scan_lock.acquire(blocking=False)  # noqa: SLF001
    try:
        assert service.scan_once_async() is False, "an in-flight loop scan blocks a one-shot"
    finally:
        service._scan_lock.release()  # noqa: SLF001


def test_localized_scan_carries_a_locale_warning(env, load_fixture) -> None:
    env["scanner"].network_text = load_fixture("netsh_show_networks_localized_es.txt")
    service = MonitoringService(env["pipeline"], interval_seconds=1)
    report = service.scan_once()
    assert report.ok
    assert len(report.warnings) == 1
    assert "non-English" in report.warnings[0]
    # Shape recovery still fed the pipeline usable signal/channel data.
    assert len(report.observations) == 2
    assert {o.channel for o in report.observations} == {44, 149}
    assert {o.signal_strength for o in report.observations} == {87, 54}


def test_english_scan_reports_no_warnings(env) -> None:
    service = MonitoringService(env["pipeline"], interval_seconds=1)
    report = service.scan_once()
    assert report.ok
    assert report.warnings == ()


def test_alert_transitions_carry_to_the_report(env) -> None:
    env["trusted"].upsert(TrustedNetwork(ssid="Guest", approved_bssids=("11:22:33:44:55:66",)))
    report = env["pipeline"].run()
    assert report.alerts
    assert all(t.alert.alert_type.value for t in report.alerts)
    active = env["manager"].active()
    assert active
    assert all(a.status is AlertStatus.ACTIVE for a in active)


# ------------------------------------------------------- frame observer evidence


def _enriched_pipeline(env, observer) -> ScanPipeline:
    """A second pipeline sharing the environment's repositories."""
    return ScanPipeline(
        scanner=env["scanner"],  # type: ignore[arg-type]
        observations=env["observations"],
        sessions=env["sessions"],
        trusted=env["trusted"],
        scores=env["scores"],
        alert_repository=env["alerts"],
        alert_manager=env["manager"],
        config=env["config"],
        prune_every=1,
        frame_observer=observer,
    )


def test_beacon_evidence_enriches_reasons_without_changing_scores(env, pipeline_env) -> None:
    """Beacon facts are appended to evidence; scores stay weight-derived.

    Both pipelines get an independent empty-history database so the
    comparison sees the identical detection context.
    """
    from app.capture import CaptureAvailability, FrameObserver
    from tests.support import MICROSOFT_OUI, FakeFrameSource, build_beacon, rsn_ie, vendor_ie

    bssid = "10:20:30:40:50:60"
    source = FakeFrameSource()
    observer = FrameObserver(
        enabled=True,
        source=source,
        availability=lambda: CaptureAvailability(True),
    )
    observer.start()
    source.feed(
        build_beacon(
            bssid=bssid,
            ies=(vendor_ie(MICROSOFT_OUI, 4), rsn_ie(caps=0)),  # WPS, no PMF
        )
    )

    enriched = _enriched_pipeline(env, observer).run()
    plain = pipeline_env["pipeline"].run()

    assert plain.ok and enriched.ok

    plain_scores = {a.identity: a.score for a in plain.assessments}
    enriched_scores = {a.identity: a.score for a in enriched.assessments}
    assert plain_scores, "fixture must produce assessments"
    assert plain_scores == enriched_scores, "evidence must never change the score"

    matching = [a for a in env["alerts"].list() if a.bssid == bssid]
    assert matching, "the fixture BSSID must produce an alert"
    reasons = matching[0].reasons
    assert any(r.startswith("beacon:") for r in reasons), reasons
    assert any("WPS" in r for r in reasons), reasons


def test_pipeline_without_observer_keeps_plain_reasons(env) -> None:
    report = env["pipeline"].run()

    assert report.ok
    for assessment in report.assessments:
        assert not any(r.startswith("beacon:") for r in assessment.reasons)
