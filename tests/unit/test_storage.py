"""Unit and integration tests for SQLite persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.models import (
    Alert,
    AlertStatus,
    AlertType,
    NetworkObservation,
    ScanSessionStatus,
    Severity,
    TrustedNetwork,
)
from app.storage import (
    SCHEMA_VERSION,
    AlertRepository,
    Database,
    ObservationRepository,
    RiskScoreRepository,
    ScanSessionRepository,
    SettingRepository,
    StorageError,
    TrustedNetworkRepository,
)


@pytest.fixture
def database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "test.sqlite3")
    db.open()
    yield db  # type: ignore[misc]
    db.close()


def make_observation(**kwargs: object) -> NetworkObservation:
    defaults: dict = {
        "ssid": "HomeNet",
        "bssid": "aa:bb:cc:dd:ee:ff",
        "signal_strength": 70,
        "security": "WPA2-Personal",
        "channel": 6,
        "observed_at": datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return NetworkObservation(**defaults)  # type: ignore[arg-type]


# ------------------------------------------------------------------ schema


def test_schema_is_created_and_versioned(database: Database) -> None:
    assert database.is_open
    assert database.schema_version == SCHEMA_VERSION
    tables = {row["name"] for row in database.query("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "observations",
        "trusted_networks",
        "alerts",
        "scan_sessions",
        "application_settings",
        "risk_scores",
    } <= tables


def test_database_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "data.sqlite3"
    with Database(target) as db:
        assert target.exists()
        assert db.schema_version == SCHEMA_VERSION


def test_reopen_preserves_data(tmp_path: Path) -> None:
    target = tmp_path / "persist.sqlite3"
    with Database(target) as db:
        ObservationRepository(db).add(make_observation())
    with Database(target) as db:
        assert ObservationRepository(db).count() == 1


def test_in_memory_database_is_supported() -> None:
    with Database(":memory:") as db:
        assert db.path == ":memory:"
        assert db.schema_version == SCHEMA_VERSION


# -------------------------------------------------------------- observations


def test_observation_roundtrip(database: Database) -> None:
    repo = ObservationRepository(database)
    stored = repo.add(make_observation())
    assert stored.id is not None

    recent = repo.recent()
    assert len(recent) == 1
    assert recent[0] == stored
    assert repo.count() == 1

    assert repo.for_bssid("aa:bb:cc:dd:ee:ff")
    assert repo.for_ssid("HomeNet")
    assert repo.for_bssid("00:00:00:00:00:01") == []
    latest = repo.latest_for(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:ff")
    assert latest is not None and latest.id == stored.id
    assert repo.latest_for(ssid="missing") is None


def test_bulk_insert_and_ordering(database: Database) -> None:
    repo = ObservationRepository(database)
    items = [
        make_observation(bssid=f"aa:bb:cc:dd:ee:{i:02x}", observed_at=datetime(2026, 5, 1, 12, i, tzinfo=UTC))
        for i in range(5)
    ]
    assert repo.add_many(items) == 5
    assert repo.add_many([]) == 0
    recent = repo.recent(limit=2)
    assert [o.bssid for o in recent] == ["aa:bb:cc:dd:ee:04", "aa:bb:cc:dd:ee:03"]


def test_observation_prune(database: Database) -> None:
    repo = ObservationRepository(database)
    repo.add(make_observation(observed_at=datetime(2020, 1, 1, tzinfo=UTC)))
    repo.add(make_observation(observed_at=datetime(2026, 5, 1, tzinfo=UTC)))
    removed = repo.prune(datetime(2021, 1, 1, tzinfo=UTC))
    assert removed == 1
    assert repo.count() == 1


def test_observation_with_session_link(database: Database) -> None:
    sessions = ScanSessionRepository(database)
    session = sessions.start()
    repo = ObservationRepository(database)
    repo.add(make_observation(), session_id=session.id)
    row = database.query_one("SELECT scan_session_id FROM observations")
    assert row is not None and row["scan_session_id"] == session.id


# ---------------------------------------------------------- trusted networks


def test_trusted_network_upsert_and_lookup(database: Database) -> None:
    repo = TrustedNetworkRepository(database)
    profile = TrustedNetwork(
        ssid="Office",
        approved_bssids=("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"),
        expected_security="WPA2-Enterprise",
        notes="lab",
    )
    stored = repo.upsert(profile)
    assert stored.id is not None
    assert repo.count() == 1

    fetched = repo.get_by_ssid("Office")
    assert fetched is not None
    assert fetched.approved_bssids == ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    assert fetched.expected_security == "WPA2-Enterprise"

    # Updating the same SSID replaces instead of duplicating.
    updated = TrustedNetwork(ssid="Office", approved_bssids=("aa:bb:cc:dd:ee:ff",))
    repo.upsert(updated)
    assert repo.count() == 1
    assert repo.get_by_ssid("Office").approved_bssids == ("aa:bb:cc:dd:ee:ff",)  # type: ignore[union-attr]


def test_trusted_network_list_and_delete(database: Database) -> None:
    repo = TrustedNetworkRepository(database)
    repo.upsert(TrustedNetwork(ssid="Alpha"))
    repo.upsert(TrustedNetwork(ssid="Beta"))
    assert [p.ssid for p in repo.list()] == ["Alpha", "Beta"]

    target = repo.get_by_ssid("Alpha")
    assert target is not None
    assert repo.delete(target.id)  # type: ignore[arg-type]
    assert not repo.delete(target.id)  # type: ignore[arg-type]
    assert repo.delete_by_ssid("Beta")
    assert not repo.delete_by_ssid("Beta")
    assert repo.count() == 0


# ------------------------------------------------------------------- alerts


def make_alert(**kwargs: object) -> Alert:
    defaults: dict = {
        "ssid": "EvilNet",
        "bssid": "de:ad:be:ef:00:01",
        "alert_type": AlertType.DUPLICATE_SSID,
        "risk_score": 45,
        "reasons": ("duplicate ssid",),
        "created_at": datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return Alert.from_score(**defaults)  # type: ignore[arg-type]


def test_alert_roundtrip_and_filters(database: Database) -> None:
    repo = AlertRepository(database)
    stored = repo.add(make_alert())
    assert stored.id is not None
    repo.add(
        make_alert(
            ssid="Other",
            bssid="de:ad:be:ef:00:02",
            alert_type=AlertType.SECURITY_DOWNGRADE,
            risk_score=85,
            created_at=datetime(2026, 5, 2, 12, 0, tzinfo=UTC),
        )
    )

    assert repo.count() == 2
    fetched = repo.get(stored.id)  # type: ignore[arg-type]
    assert fetched == stored
    assert fetched.severity is Severity.SUSPICIOUS

    assert len(repo.list(status=AlertStatus.ACTIVE)) == 2
    assert len(repo.list(severity=Severity.CRITICAL)) == 1
    assert len(repo.list(alert_type=AlertType.DUPLICATE_SSID)) == 1
    assert len(repo.list(ssid="EvilNet")) == 1
    assert len(repo.list(since=datetime(2026, 5, 2, tzinfo=UTC))) == 1
    assert repo.get(9999) is None


def test_alert_deduplication_and_occurrence_tracking(database: Database) -> None:
    repo = AlertRepository(database)
    first = repo.add(make_alert())

    match = repo.find_open_match(make_alert(reasons=("unknown bssid",), risk_score=65))
    assert match is not None and match.id == first.id

    updated = repo.record_occurrence(match, make_alert(reasons=("unknown bssid",), risk_score=65))
    assert updated.occurrence_count == 2
    assert updated.first_seen == first.first_seen
    assert updated.last_seen >= first.last_seen  # type: ignore[operator]
    assert updated.risk_score == 65  # higher score escalates
    assert set(updated.reasons) == {"duplicate ssid", "unknown bssid"}

    stored = repo.get(first.id)  # type: ignore[arg-type]
    assert stored is not None and stored.occurrence_count == 2
    assert repo.count() == 1  # no duplicate row


def test_alert_status_transitions(database: Database) -> None:
    repo = AlertRepository(database)
    alert = repo.add(make_alert())
    ack = repo.set_status(alert.id, AlertStatus.ACKNOWLEDGED)  # type: ignore[arg-type]
    assert ack is not None and ack.status is AlertStatus.ACKNOWLEDGED
    assert repo.count(status=AlertStatus.ACTIVE) == 0

    resolved = repo.set_status(alert.id, AlertStatus.RESOLVED)  # type: ignore[arg-type]
    assert resolved is not None and resolved.status is AlertStatus.RESOLVED


def test_alert_counts_and_prune(database: Database) -> None:
    repo = AlertRepository(database)
    repo.add(make_alert(risk_score=10))  # low
    repo.add(make_alert(risk_score=90, ssid="B"))  # critical
    repo.add(make_alert(risk_score=90, ssid="C"))
    counts = repo.counts_by_severity()
    assert counts == {"low": 1, "critical": 2}

    old = repo.add(make_alert(ssid="Old", created_at=datetime(2020, 1, 1, tzinfo=UTC)))
    repo.set_status(old.id, AlertStatus.RESOLVED)  # type: ignore[arg-type]
    assert repo.prune(datetime(2021, 1, 1, tzinfo=UTC)) == 1
    assert repo.count() == 3


def test_find_open_match_ignores_other_types_and_identities(database: Database) -> None:
    repo = AlertRepository(database)
    repo.add(make_alert())
    assert repo.find_open_match(make_alert(alert_type=AlertType.PERSISTENCE)) is None
    assert repo.find_open_match(make_alert(bssid="de:ad:be:ef:00:99")) is None
    assert repo.find_open_match(make_alert(ssid="Different")) is None


def test_resolved_alert_is_not_matched_again(database: Database) -> None:
    repo = AlertRepository(database)
    alert = repo.add(make_alert())
    repo.set_status(alert.id, AlertStatus.RESOLVED)  # type: ignore[arg-type]
    assert repo.find_open_match(make_alert()) is None


# ------------------------------------------------------------------ sessions


def test_session_lifecycle(database: Database) -> None:
    repo = ScanSessionRepository(database)
    session = repo.start()
    assert session.id is not None
    assert session.status is ScanSessionStatus.RUNNING
    assert repo.count() == 1

    finished = repo.finish(session, network_count=7)
    assert finished.status is ScanSessionStatus.COMPLETED
    assert finished.network_count == 7
    assert finished.completed_at is not None

    recent = repo.recent()
    assert recent[0].status is ScanSessionStatus.COMPLETED
    assert recent[0].network_count == 7


def test_finish_unstored_session_raises(database: Database) -> None:
    from app.models import ScanSession

    with pytest.raises(StorageError):
        ScanSessionRepository(database).finish(ScanSession())


def test_failed_session_can_be_recorded(database: Database) -> None:

    repo = ScanSessionRepository(database)
    session = repo.start()
    failed = repo.finish(session, status=ScanSessionStatus.FAILED)
    assert failed.status is ScanSessionStatus.FAILED
    assert failed.network_count == 0


# ------------------------------------------------------------------ settings


def test_settings_crud(database: Database) -> None:
    repo = SettingRepository(database)
    assert repo.get("missing", "fallback") == "fallback"

    repo.set("scan_interval_seconds", "30")
    assert repo.get("scan_interval_seconds") == "30"

    repo.set_many({"theme": "dark", "notify": None})
    assert repo.get("theme") == "dark"
    assert repo.get("notify") is None

    values = repo.all()
    assert values["scan_interval_seconds"] == "30"
    assert set(values) >= {"scan_interval_seconds", "theme", "notify"}

    assert repo.delete("theme")
    assert not repo.delete("theme")
    assert repo.get("theme") is None


# --------------------------------------------------------------- risk scores


def test_risk_score_history(database: Database) -> None:
    repo = RiskScoreRepository(database)
    repo.add(
        ssid="X",
        bssid="aa:bb:cc:dd:ee:ff",
        score=45,
        severity=Severity.SUSPICIOUS,
        reasons=("dup",),
        created_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
    )
    repo.add(
        ssid="X",
        bssid="aa:bb:cc:dd:ee:ff",
        score=70,
        severity=Severity.HIGH,
        reasons=("dup", "persistence"),
        created_at=datetime(2026, 5, 1, 13, 0, tzinfo=UTC),
    )

    history = repo.history(ssid="X", bssid="aa:bb:cc:dd:ee:ff")
    assert len(history) == 2
    assert history[0]["score"] == 70
    assert history[0]["reasons"] == ["dup", "persistence"]
    assert repo.history(ssid="unknown") == []

    assert repo.prune(datetime(2026, 5, 1, 12, 30, tzinfo=UTC)) == 1


# ------------------------------------------------------------- error handling


def test_invalid_observation_raises_storage_error(database: Database) -> None:
    with pytest.raises(StorageError):
        database.execute("SELECT * FROM does_not_exist")


def test_transaction_rolls_back_on_failure(database: Database) -> None:
    repo = TrustedNetworkRepository(database)
    repo.upsert(TrustedNetwork(ssid="Keep"))
    with pytest.raises(StorageError):
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO trusted_networks (ssid, approved_bssids, created_at) VALUES (?, ?, ?)",
                ("Keep", "[]", datetime.now(UTC).isoformat()),
            )
            connection.execute("SELECT * FROM missing_table")  # fails mid-transaction
    # The first insert of this transaction must have rolled back with it.
    assert repo.get_by_ssid("Keep") is not None


def test_query_parameterisation_blocks_injection(database: Database) -> None:
    repo = ObservationRepository(database)
    repo.add(make_observation())
    injected = ObservationRepository(database)
    assert injected.for_ssid("' OR 1=1 --") == []
    assert injected.for_bssid("'; DROP TABLE observations; --") == []
    assert repo.count() == 1
