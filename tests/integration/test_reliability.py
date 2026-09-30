"""Reliability review (Prompt 18): failures must degrade, never crash.

Covered here: unavailable adapters, failing and raising scanner commands,
empty and malformed output, storage failures, application restarts and rapid
monitoring lifecycle changes. No test needs a live wireless environment.
"""

from __future__ import annotations

import time
from pathlib import Path

from app.alerts import AlertManager, NullNotifier
from app.core.config import Config
from app.models import ScanSessionStatus
from app.services import MonitoringService, ScanPipeline
from app.storage import (
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    TrustedNetworkRepository,
)
from tests.support import FakeScanner

TIMEOUT = 10.0


def _wait_until(predicate, timeout: float = TIMEOUT) -> bool:  # noqa: ANN001
    """Poll ``predicate`` briefly instead of relying on fixed sleeps."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _build_pipeline(database: Database, scanner: FakeScanner) -> ScanPipeline:
    """Wire a fresh pipeline over ``database`` (used for restart tests)."""
    config = Config()
    alerts = AlertRepository(database)
    return ScanPipeline(
        scanner=scanner,  # type: ignore[arg-type]
        observations=ObservationRepository(database),
        sessions=ScanSessionRepository(database),
        trusted=TrustedNetworkRepository(database),
        scores=RiskScoreRepository(database),
        alert_repository=alerts,
        alert_manager=AlertManager(alerts, config=config, notifier=NullNotifier()),
        config=config,
        prune_every=1,
    )


# ---------------------------------------------------------------- storage


def test_closed_database_becomes_error_report(pipeline_env) -> None:
    """A dead connection (storage failure) must be reported, not raised."""
    pipeline_env["database"].connection.close()  # handle dies underneath us

    report = pipeline_env["pipeline"].run()

    assert not report.ok
    assert "storage" in (report.error or "")
    assert report.session.status is ScanSessionStatus.FAILED
    # No session row could be written, so history counts stay untouched.
    assert pipeline_env["pipeline"].last_error == report.error


def test_storage_failure_does_not_poison_the_next_scan(pipeline_env) -> None:
    """Once storage recovers, monitoring continues normally."""
    database = pipeline_env["database"]
    database.connection.close()
    assert not pipeline_env["pipeline"].run().ok

    # Recovery: discard the dead handle and reopen the same file.
    database.close()
    database.open()

    report = pipeline_env["pipeline"].run()
    assert report.ok, report.error
    assert report.network_count == 4
    assert database.is_open


# ---------------------------------------------------------------- scanner


def test_raising_scanner_becomes_error_report(pipeline_env, monkeypatch) -> None:
    """An unexpected exception inside netsh handling is contained."""
    scanner = pipeline_env["scanner"]

    def explode() -> object:
        raise RuntimeError("radio exploded")

    monkeypatch.setattr(scanner, "scan", explode)

    report = pipeline_env["pipeline"].run()

    assert not report.ok
    assert "radio exploded" in (report.error or "")
    assert report.session.status is ScanSessionStatus.FAILED
    # The failed session is persisted so history shows the gap.
    assert pipeline_env["sessions"].count() == 1
    assert pipeline_env["sessions"].recent(limit=10)[0].status is ScanSessionStatus.FAILED


def test_failed_command_output_is_surfaced(pipeline_env, load_fixture) -> None:
    """netsh exiting non-zero (service not running) yields a readable error."""
    scanner = pipeline_env["scanner"]
    scanner.network_text = load_fixture("netsh_service_not_running.txt")
    scanner.scan_ok = False

    report = pipeline_env["pipeline"].run()

    assert not report.ok
    assert report.error


def test_malformed_output_is_partially_recovered(pipeline_env, load_fixture) -> None:
    """Parser tolerance: garbage input never crashes a scan, valid rows survive."""
    pipeline_env["scanner"].network_text = load_fixture("netsh_show_networks_malformed.txt")

    report = pipeline_env["pipeline"].run()

    assert report.ok, report.error
    # Networks parsed before the garbage still make it into history.
    assert report.network_count >= 1
    assert report.session.status is ScanSessionStatus.COMPLETED


def test_binary_junk_output_is_survivable(pipeline_env) -> None:
    """Even non-text bytes must not raise."""
    pipeline_env["scanner"].network_text = "SSID \x00\x01\x02\r\n\t\r\n\x00 gibberish: %%"

    report = pipeline_env["pipeline"].run()

    assert report.ok, report.error


# ------------------------------------------------------------- restart


def test_restart_reloads_history_and_suppresses_new_ap_rule(pipeline_env, load_fixture) -> None:
    """Closing and reopening the app keeps the learned environment."""
    first = pipeline_env["pipeline"].run()
    assert first.ok
    expected_bssids = {
        observation.bssid
        for observation in first.observations
        if observation.bssid is not None
    }
    assert expected_bssids
    path = Path(pipeline_env["path"])
    pipeline_env["database"].close()

    # --- simulated application restart ---------------------------------
    reopened = Database(path)
    reopened.open()
    try:
        scanner = FakeScanner(
            network_text=load_fixture("netsh_show_networks_multi.txt"),
            interface_text=load_fixture("netsh_show_interfaces_connected.txt"),
        )
        pipeline = _build_pipeline(reopened, scanner)
        report = pipeline.run()

        assert report.ok, report.error
        assert pipeline.known_bssids_count == len(expected_bssids)
        rules = {finding.rule.value for finding in report.findings}
        # Everything was already known: the new-access-point rule stays quiet.
        assert "new_access_point" not in rules
        assert reopened.schema_version >= 1
        assert ScanSessionRepository(reopened).count() == 2
    finally:
        reopened.close()


# ------------------------------------------------------------ lifecycle


def test_rapid_start_stop_cycles(pipeline_env) -> None:
    """Toggling monitoring quickly must always end in a clean state."""
    service = MonitoringService(pipeline_env["pipeline"], interval_seconds=1)

    for cycle in range(5):
        assert service.start(), f"cycle {cycle} failed to start"
        assert service.is_running, f"cycle {cycle} not running"
        assert service.stop(timeout=TIMEOUT), f"cycle {cycle} failed to stop"
        assert not service.is_running, f"cycle {cycle} still running"

    assert service.last_report is not None
    assert pipeline_env["scanner"].scan_calls >= 1


def test_service_restarts_after_stop(pipeline_env) -> None:
    """A stopped service can be started again and scans resume."""
    scanner = pipeline_env["scanner"]
    service = MonitoringService(pipeline_env["pipeline"], interval_seconds=60)

    assert service.start()
    assert _wait_until(lambda: scanner.scan_calls >= 1)
    assert service.stop(timeout=TIMEOUT)

    calls_after_first_run = scanner.scan_calls
    assert service.start()
    assert _wait_until(lambda: scanner.scan_calls > calls_after_first_run)
    assert service.stop(timeout=TIMEOUT)
    assert not service.is_running


def test_stop_without_start_is_safe(pipeline_env) -> None:
    """Double stop and stop-before-start must not raise."""
    service = MonitoringService(pipeline_env["pipeline"], interval_seconds=1)
    assert service.stop(timeout=1.0) is False
    assert service.stop(timeout=1.0) is False


def test_raising_callbacks_do_not_break_error_reporting(pipeline_env) -> None:
    """A dead UI callback must not stop the monitoring loop."""
    scanner = pipeline_env["scanner"]
    scanner.usable = (False, "no wireless interfaces are present")

    def dead_ui(_message: str) -> None:
        raise RuntimeError("ui thread gone")

    service = MonitoringService(pipeline_env["pipeline"], on_error=dead_ui)
    report = service.scan_once()

    assert not report.ok
    assert service.last_report is report
