"""Shared pytest configuration: fixtures and repository import path."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.alerts import AlertManager, NullNotifier  # noqa: E402
from app.core.config import Config  # noqa: E402
from app.services import ScanPipeline  # noqa: E402
from app.storage import (  # noqa: E402
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    TrustedNetworkRepository,
)
from tests.support import FakeScanner  # noqa: E402

NETWORKS_FIXTURE = "netsh_show_networks_multi.txt"
INTERFACES_FIXTURE = "netsh_show_interfaces_connected.txt"


@pytest.fixture
def load_fixture() -> Callable[[str], str]:
    """Return a loader that reads a sanitized scanner-output fixture."""

    def _load(name: str) -> str:
        path = FIXTURES / name
        assert path.is_file(), f"missing fixture: {name}"
        return path.read_text(encoding="utf-8")

    return _load


@pytest.fixture
def pipeline_env(tmp_path: Path, load_fixture: Callable[[str], str]) -> dict:
    """Fully wired pipeline over a temporary database with a fake scanner.

    Shared by integration tests that exercise scan -> detect -> persist.
    """
    database = Database(tmp_path / "reliability.sqlite3")
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
        "path": database.path,
    }
    database.close()
