"""Configuration changes must reach the running services (quality audit fix).

Saving settings previously updated only the config file and the context's
attributes; the scan pipeline kept the configuration it was constructed with,
so weights, thresholds, retention and notification settings silently did
nothing until restart. These tests pin the corrected behaviour.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from app.alerts import NullNotifier
from app.core.config import Config, RiskWeights
from app.core.context import AppContext
from app.services import MonitoringService
from tests.support import FakeScanner

NETWORKS_FIXTURE = "netsh_show_networks_multi.txt"
INTERFACES_FIXTURE = "netsh_show_interfaces_connected.txt"


def _context(tmp_path: Path, load_fixture) -> AppContext:  # noqa: ANN001
    scanner = FakeScanner(
        network_text=load_fixture(NETWORKS_FIXTURE),
        interface_text=load_fixture(INTERFACES_FIXTURE),
    )
    return AppContext(
        config_path=tmp_path / "config.json",
        config=Config(),
        notifier=NullNotifier(),
        scanner=scanner,  # type: ignore[arg-type]
    )


def _scores(context: AppContext) -> dict[tuple[str | None, str | None], int]:
    return {
        (entry["ssid"], entry["bssid"]): int(entry["score"])
        for entry in context.scores.latest_scores(limit=500)
    }


# --------------------------------------------------------------- pipeline


def test_pipeline_apply_config_replaces_scorer_and_config(pipeline_env) -> None:
    pipeline = pipeline_env["pipeline"]
    original_scorer = pipeline.scorer
    updated = replace(pipeline.config, suspicious_threshold=40)

    pipeline.apply_config(updated)

    assert pipeline.config is updated
    assert pipeline.scorer is not original_scorer
    assert pipeline.config.suspicious_threshold == 40


def test_pipeline_apply_config_keeps_alert_manager(pipeline_env) -> None:
    pipeline = pipeline_env["pipeline"]
    original_manager = pipeline._alert_manager  # noqa: SLF001

    pipeline.apply_config(pipeline.config)

    assert pipeline._alert_manager is original_manager  # noqa: SLF001


# ---------------------------------------------------------------- context


def test_saved_weights_change_alert_scores(tmp_path: Path, load_fixture) -> None:
    """End to end: lowering the duplicate-SSID weight lowers real scores."""
    context = _context(tmp_path, load_fixture)
    try:
        assert context.monitoring.scan_once().ok
        before = _scores(context)
        corporate_keys = [key for key in before if key[0] == "Corporate"]
        assert corporate_keys, "fixture must contain the duplicate Corporate SSID"
        assert any(score > 0 for score in before.values())

        weights = replace(context.config.risk_weights, duplicate_ssid=1)
        context.save_config(replace(context.config, risk_weights=weights))

        assert context.monitoring.scan_once().ok
        after = _scores(context)
        for key in corporate_keys:
            assert after[key] < before[key], f"{key} score unchanged after weight change"
    finally:
        context.close()


def test_save_config_updates_idle_monitoring_interval(tmp_path: Path, load_fixture) -> None:
    """A stopped service picks up the new interval on the next save."""
    context = _context(tmp_path, load_fixture)
    try:
        assert context.monitoring.interval_seconds == 15
        context.save_config(replace(context.config, scan_interval_seconds=45))

        assert context.monitoring.interval_seconds == 45
        assert not context.monitoring.is_running
        assert context.config_path.exists()
    finally:
        context.close()


def test_save_config_restarts_running_monitoring_and_keeps_callbacks(
    tmp_path: Path, load_fixture
) -> None:
    """A running loop adopts the new cadence without losing its callbacks."""
    context = _context(tmp_path, load_fixture)
    seen: list[object] = []
    try:
        context.set_callbacks(on_report=seen.append, on_error=lambda _m: None)
        context.monitoring.start()
        assert context.monitoring.is_running

        context.save_config(replace(context.config, scan_interval_seconds=45))

        assert context.monitoring.is_running, "loop must keep running after the change"
        assert context.monitoring.interval_seconds == 45
        assert context.monitoring.on_report is not None

        # The rebuilt service still reports through the original callback.
        context.monitoring.scan_once()
        assert seen, "callback was lost across the configuration change"
    finally:
        context.close()


def test_apply_config_points_context_at_pipeline_objects(tmp_path: Path, load_fixture) -> None:
    """The context must expose the exact engine/scorer the scans will use."""
    context = _context(tmp_path, load_fixture)
    try:
        context.save_config(replace(context.config, critical_threshold=70))

        assert context.engine is context.pipeline.engine
        assert context.scorer is context.pipeline.scorer
        assert context.pipeline.config is context.config
    finally:
        context.close()


def test_save_config_keeps_alert_manager_state(tmp_path: Path, load_fixture) -> None:
    """Rebuilding the manager on save would reset notification cooldowns."""
    context = _context(tmp_path, load_fixture)
    try:
        manager = context.alert_manager
        notifier = manager.notifier

        context.save_config(replace(context.config, notifications_enabled=False))

        assert context.alert_manager is manager
        assert context.alert_manager.notifier is notifier
        assert context.alert_manager.config is context.config
        assert context.pipeline.config is context.config
    finally:
        context.close()


def test_retention_change_reaches_pipeline(tmp_path: Path, load_fixture) -> None:
    """The retention window read during pruning comes from the new config."""
    context = _context(tmp_path, load_fixture)
    try:
        context.save_config(replace(context.config, data_retention_days=7))
        assert context.pipeline.config.data_retention_days == 7

        context.save_config(
            replace(
                context.config,
                risk_weights=RiskWeights(),
                notifications_enabled=False,
            )
        )
        assert context.pipeline.config.notifications_enabled is False
    finally:
        context.close()


def test_new_monitoring_service_defaults_match_context(tmp_path: Path, load_fixture) -> None:
    """Guard against the service/context cadence drifting apart."""
    context = _context(tmp_path, load_fixture)
    try:
        fresh = MonitoringService(context.pipeline, interval_seconds=15)
        assert fresh.interval_seconds == context.monitoring.interval_seconds
    finally:
        context.close()
