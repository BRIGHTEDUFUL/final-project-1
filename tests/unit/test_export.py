"""Unit tests for CSV export (Prompt 16/20): correctness, atomicity, safety."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.models import Alert, AlertType, NetworkObservation
from app.services.export import (
    ALERT_COLUMNS,
    OBSERVATION_COLUMNS,
    ExportError,
    export_alerts_csv,
    export_observations_csv,
)


def make_alert(**kwargs: object) -> Alert:
    defaults: dict = {
        "ssid": "Corporate",
        "bssid": "10:20:30:40:50:60",
        "alert_type": AlertType.DUPLICATE_SSID,
        "risk_score": 45,
        "reasons": ("duplicate ssid observed", "unknown bssid"),
        "created_at": datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return Alert.from_score(**defaults)  # type: ignore[arg-type]


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


def read_rows(path: Path) -> tuple[list[str], list[list[str]]]:
    text = path.read_text(encoding="utf-8-sig")
    # Feed csv a stream (not split lines) so quoted newlines stay intact.
    rows = list(csv.reader(io.StringIO(text)))
    return (rows[0] if rows else []), rows[1:]


def row_dict(header: list[str], row: list[str]) -> dict[str, str]:
    """Zip a header and a data row into a mapping (lengths are asserted)."""
    assert len(header) == len(row), f"ragged row: {header!r} vs {row!r}"
    return dict(zip(header, row, strict=True))


# ----------------------------------------------------------------- alerts


def test_alerts_export_writes_header_and_values(tmp_path: Path) -> None:
    target = tmp_path / "out" / "alerts.csv"

    written = export_alerts_csv(target, [make_alert()])

    assert written == target
    assert target.is_file()
    header, rows = read_rows(target)
    assert header == list(ALERT_COLUMNS)
    assert len(rows) == 1
    row = row_dict(header, rows[0])
    assert row["ssid"] == "Corporate"
    assert row["bssid"] == "10:20:30:40:50:60"
    assert row["risk_score"] == "45"
    assert row["severity"] == "suspicious"
    assert row["status"] == "active"
    assert row["alert_type"] == "duplicate_ssid"


def test_alerts_export_joins_reasons(tmp_path: Path) -> None:
    export_alerts_csv(tmp_path / "a.csv", [make_alert()])
    header, rows = read_rows(tmp_path / "a.csv")
    reasons = row_dict(header, rows[0])["reasons"]
    assert reasons == "duplicate ssid observed | unknown bssid"


def test_alerts_export_handles_missing_identity_and_timestamps(tmp_path: Path) -> None:
    # Alert requires at least one identity component: drop the SSID only.
    alert = make_alert(ssid=None)
    export_alerts_csv(tmp_path / "hidden.csv", [alert])
    header, rows = read_rows(tmp_path / "hidden.csv")
    row = row_dict(header, rows[0])
    assert row["ssid"] == ""
    assert row["bssid"] == "10:20:30:40:50:60"
    expected_first = alert.first_seen.isoformat() if alert.first_seen else ""
    assert row["first_seen"] == expected_first


# ------------------------------------------------------------ observations


def test_observations_export_maps_empty_fields(tmp_path: Path) -> None:
    # An observation needs one identity component: keep the BSSID, drop the rest.
    observation = make_observation(
        ssid=None,
        signal_strength=None,
        security=None,
        channel=None,
    )
    export_observations_csv(tmp_path / "obs.csv", [observation])

    header, rows = read_rows(tmp_path / "obs.csv")
    assert header == list(OBSERVATION_COLUMNS)
    row = row_dict(header, rows[0])
    assert row["ssid"] == ""
    assert row["bssid"] == "aa:bb:cc:dd:ee:ff"
    assert row["signal_strength"] == ""
    assert row["security"] == ""
    assert row["channel"] == ""


def test_empty_export_writes_header_only(tmp_path: Path) -> None:
    target = tmp_path / "empty.csv"
    export_alerts_csv(target, [])
    header, rows = read_rows(target)
    assert header == list(ALERT_COLUMNS)
    assert rows == []


def test_missing_parent_directories_are_created(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "c" / "obs.csv"
    export_observations_csv(target, [make_observation()])
    assert target.is_file()


# -------------------------------------------------------------- file safety


def test_export_is_utf8_with_bom(tmp_path: Path) -> None:
    target = tmp_path / "bom.csv"
    export_alerts_csv(target, [make_alert(ssid="Café 📡")])
    raw = target.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "spreadsheet software needs the BOM"
    header, rows = read_rows(target)
    assert row_dict(header, rows[0])["ssid"] == "Café 📡"


def test_special_characters_round_trip(tmp_path: Path) -> None:
    tricky = 'Guest, "VIP"; pass\tword\nline2'
    target = tmp_path / "tricky.csv"
    export_alerts_csv(target, [make_alert(ssid=tricky)])
    header, rows = read_rows(target)
    assert row_dict(header, rows[0])["ssid"] == tricky


def test_overwrite_replaces_content_without_temp_leftovers(tmp_path: Path) -> None:
    target = tmp_path / "alerts.csv"
    export_alerts_csv(target, [make_alert()])
    export_alerts_csv(target, [make_alert(ssid="Second"), make_alert(ssid="Third")])

    _, rows = read_rows(target)
    assert len(rows) == 2
    assert not (tmp_path / "alerts.csv.tmp").exists()


def test_exporting_over_a_directory_raises_export_error(tmp_path: Path) -> None:
    directory = tmp_path / "is-a-directory"
    directory.mkdir()
    with pytest.raises(ExportError, match="is not a file"):
        export_alerts_csv(directory, [])


def test_unwritable_parent_raises_export_error_not_oserror(tmp_path: Path) -> None:
    """mkdir failures must surface as ExportError (the UI catches that type)."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ExportError, match="cannot write"):
        export_alerts_csv(blocker / "alerts.csv", [make_alert()])

    assert not (blocker / "alerts.csv.tmp").exists()


def test_failed_export_preserves_previous_file(tmp_path: Path) -> None:
    """A failed overwrite never destroys the previously exported report."""
    target = tmp_path / "alerts.csv"
    export_alerts_csv(target, [make_alert(ssid="Original")])

    # Make the *temporary* path unusable by occupying it with a directory:
    # writing the new file fails after the old one still exists.
    tmp_file = tmp_path / "alerts.csv.tmp"
    tmp_file.mkdir()
    with pytest.raises(ExportError):
        export_alerts_csv(target, [make_alert(ssid="Replacement")])

    _, rows = read_rows(target)
    assert len(rows) == 1
    assert row_dict(list(ALERT_COLUMNS), rows[0])["ssid"] == "Original"
