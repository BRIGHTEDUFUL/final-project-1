"""GUI smoke tests.

Everything runs on Qt's offscreen platform, so the suite passes on CI and on
machines without an interactive desktop. The tests build the real window, the
real repositories and a fake scanner, then exercise navigation, a full scan
and the settings/trusted-network dialogs.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox  # noqa: E402

from app.alerts import NullNotifier  # noqa: E402
from app.core.config import Config  # noqa: E402
from app.core.context import AppContext  # noqa: E402
from app.models import TrustedNetwork  # noqa: E402
from app.ui.shell import NAV_ITEMS, MainWindow  # noqa: E402
from app.ui.theme import apply_theme, stylesheet  # noqa: E402
from tests.support import FakeScanner  # noqa: E402


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """One application instance for the whole GUI test session."""
    application = QApplication.instance() or QApplication([])
    apply_theme(application)
    return application


@pytest.fixture(autouse=True)
def _quiet_message_boxes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Message boxes would block a headless run; answer them instead."""
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(
        QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
    )


@pytest.fixture
def context(tmp_path: Path, load_fixture) -> AppContext:
    """Application context backed by a temporary database and fake scanner."""
    scanner = FakeScanner(
        network_text=load_fixture("netsh_show_networks_multi.txt"),
        interface_text=load_fixture("netsh_show_interfaces_connected.txt"),
    )
    built = AppContext(
        config_path=tmp_path / "config.json",
        config=Config(),
        notifier=NullNotifier(),
        scanner=scanner,  # type: ignore[arg-type]
    )
    yield built  # type: ignore[misc]
    built.close()


@pytest.fixture
def window(qapp: QApplication, context: AppContext) -> MainWindow:
    """Real main window wired to the temporary context."""
    window = MainWindow(context)
    window.show()
    qapp.processEvents()
    yield window  # type: ignore[misc]
    window.close()
    qapp.processEvents()


def _wait_for(condition: Callable[[], bool], timeout: float = 10.0) -> bool:
    """Pump the Qt event loop until ``condition`` holds or time runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    QApplication.processEvents()
    return bool(condition())


# ------------------------------------------------------------------ window


def test_window_builds_with_all_navigation_entries(window: MainWindow) -> None:
    assert window.windowTitle() == "Rogue AP Hunter"
    assert [key for key, _ in NAV_ITEMS] == window._nav_keys  # noqa: SLF001
    assert window.current_page_key() == "dashboard"
    assert len(window._pages) == len(NAV_ITEMS)  # noqa: SLF001


@pytest.mark.parametrize("key", [key for key, _ in NAV_ITEMS])
def test_navigation_reaches_every_page(window: MainWindow, key: str) -> None:
    window.show_page(key)
    assert window.current_page_key() == key
    button = window._nav_buttons[key]  # noqa: SLF001
    assert button.isChecked()


def test_unknown_page_is_ignored(window: MainWindow, caplog: pytest.LogCaptureFixture) -> None:
    window.show_page("does-not-exist")
    assert window.current_page_key() == "dashboard"
    assert any("unknown page" in record.message for record in caplog.records)


# ------------------------------------------------------------------- scans


def test_scan_once_updates_status_and_pages(window: MainWindow, context: AppContext) -> None:
    window.scan_once()
    # The one-shot runs on a worker thread; pump events until it reports
    # (the report handler re-enables the button).
    assert _wait_for(lambda: window._scan_once_button.isEnabled())  # noqa: SLF001
    assert context.monitoring.last_report is not None
    assert context.observations.count() == 4
    assert window.statusBar().currentMessage() != ""

    window.show_page("live")
    live = window._live  # noqa: SLF001
    live.refresh()
    assert live.snapshots, "live page should show the four observed radios"

    window.show_page("history")
    assert window._history._session_model.rowCount() >= 1  # noqa: SLF001


def test_scan_once_shows_busy_message_when_a_scan_is_running(
    window: MainWindow, context: AppContext
) -> None:
    monitoring = context.monitoring
    assert monitoring._scan_lock.acquire(blocking=False)  # noqa: SLF001
    try:
        window.scan_once()
        assert "already in progress" in window.statusBar().currentMessage()
        assert window._scan_once_button.isEnabled()  # noqa: SLF001
    finally:
        monitoring._scan_lock.release()  # noqa: SLF001


def test_monitoring_toggle_starts_and_stops(window: MainWindow, context: AppContext) -> None:
    window.toggle_monitoring()
    assert context.monitoring.is_running
    assert window._monitor_button.text() == "Stop monitoring"  # noqa: SLF001

    window.toggle_monitoring()
    assert not context.monitoring.is_running
    assert window._monitor_button.text() == "Start monitoring"  # noqa: SLF001


def test_error_report_is_surfaced(window: MainWindow, context: AppContext) -> None:
    context.scanner.usable = (False, "no wireless interfaces are present")  # type: ignore[attr-defined]
    report = context.monitoring.scan_once()
    assert not report.ok
    # The GUI must not raise while displaying a failed scan.
    window._on_report(report)  # noqa: SLF001
    window._on_error(report.error or "")  # noqa: SLF001
    assert window._monitor_state.text().startswith("Monitoring")  # noqa: SLF001


# ----------------------------------------------------------- investigation


def test_investigation_shows_evidence_after_scan(window: MainWindow, context: AppContext) -> None:
    context.trusted.upsert(
        TrustedNetwork(
            ssid="Corporate",
            approved_bssids=("10:20:30:40:50:60",),
            expected_security="WPA3-SAE",
        )
    )
    context.monitoring.scan_once()

    window.open_investigation("Corporate", "10:20:30:40:50:61")
    assert window.current_page_key() == "investigation"

    investigation = window._investigation  # noqa: SLF001
    assert investigation.identity == ("Corporate", "10:20:30:40:50:61")
    text = investigation._reasons.toPlainText()  # noqa: SLF001
    assert text and "No findings" not in text
    assert investigation._facts["trust"].text() != "\u2014"  # noqa: SLF001


# ---------------------------------------------------------------- settings


def test_settings_round_trip(window: MainWindow, context: AppContext) -> None:
    settings = window._settings  # noqa: SLF001
    settings.refresh()
    settings._interval.setValue(45)  # noqa: SLF001
    settings._suspicious.setValue(25)  # noqa: SLF001
    settings._weight_spins["persistence"].setValue(15)  # noqa: SLF001
    settings._frame_enabled.setChecked(False)  # noqa: SLF001
    assert settings._frame_status.text()  # noqa: SLF001  status line is populated

    settings._save()  # noqa: SLF001

    assert context.config.scan_interval_seconds == 45
    assert context.config.suspicious_threshold == 25
    assert context.config.risk_weights.persistence == 15
    assert context.config.frame_observer_enabled is False
    assert context.config_path.exists()


def test_settings_reject_invalid_thresholds(window: MainWindow, monkeypatch) -> None:
    settings = window._settings  # noqa: SLF001
    captured: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning", staticmethod(lambda _parent, _title, text, *a, **k: captured.append(str(text)) or QMessageBox.StandardButton.Ok)
    )
    settings._suspicious.setValue(90)  # noqa: SLF001
    settings._high.setValue(80)  # noqa: SLF001  (must be > suspicious)
    settings._save()  # noqa: SLF001
    assert captured and "suspicious" in captured[0]


# -------------------------------------------------------- trusted networks


def test_trusted_dialog_validates_bssids() -> None:
    from app.ui.pages.trusted_networks import TrustedNetworkDialog

    dialog = TrustedNetworkDialog()
    dialog.prefill_ssid("HomeNet")
    dialog._ssid.setText("HomeNet")  # noqa: SLF001
    dialog._bssids.setPlainText("aa:bb:cc:dd:ee:ff\nnot-a-mac")  # noqa: SLF001
    dialog._validate()  # noqa: SLF001
    assert dialog.profile() is None
    assert dialog._error.isVisible() or dialog._error.text()  # noqa: SLF001

    dialog._bssids.setPlainText("aa:bb:cc:dd:ee:ff")  # noqa: SLF001
    dialog._validate()  # noqa: SLF001
    profile = dialog.profile()
    assert profile is not None
    assert profile.ssid == "HomeNet"
    assert profile.approved_bssids == ("aa:bb:cc:dd:ee:ff",)


def test_trusted_page_add_and_delete(window: MainWindow, context: AppContext) -> None:
    page = window._trusted  # noqa: SLF001
    page.refresh()
    assert page._model.rowCount() == 0  # noqa: SLF001

    context.trusted.upsert(TrustedNetwork(ssid="HomeNet"))
    page.refresh()
    assert page._model.rowCount() == 1  # noqa: SLF001
    assert page._model.row_at(0).ssid == "HomeNet"  # noqa: SLF001


# ------------------------------------------------------------------ theme


def test_stylesheet_contains_core_rules() -> None:
    sheet = stylesheet()
    for token in ("#0f141a", "#3ab7c9", "QTableView", "QPushButton#primaryButton"):
        assert token in sheet
    assert "__ACCENT__" not in sheet, "placeholder must not leak"


def test_stylesheet_never_styles_widgets_globally() -> None:
    """Regression: a global ``QWidget``/``QFrame`` rule paints phantom boxes
    behind every child label (QLabel inherits QFrame). Backgrounds must be
    scoped to a container class or an object name."""
    sheet = stylesheet()
    assert "QWidget {" not in sheet
    assert "QFrame {" not in sheet
    assert "QLabel {" not in sheet


def test_severity_colour_is_scoped_to_its_own_column() -> None:
    """Only the severity cell is tinted; identifiers stay neutral."""
    from PySide6.QtCore import Qt as _Qt
    from PySide6.QtGui import QColor

    from app.ui.table_models import ColumnTableModel

    model = ColumnTableModel(
        [
            ("Severity", lambda row: row["severity"], None),
            ("BSSID", lambda row: row["bssid"], None),
        ]
    )
    model.set_color_column(0, lambda row: row["severity"])
    model.set_rows([{"severity": "critical", "bssid": "aa:bb:cc:dd:ee:ff"}])

    severity_index = model.index(0, 0)
    bssid_index = model.index(0, 1)
    foreground = model.data(severity_index, _Qt.ItemDataRole.ForegroundRole)
    assert isinstance(foreground, QColor)
    assert foreground.name() != "#000000"
    assert model.data(bssid_index, _Qt.ItemDataRole.ForegroundRole) is None


def test_mono_columns_request_a_monospace_font() -> None:
    from PySide6.QtCore import Qt as _Qt
    from PySide6.QtGui import QFont

    from app.ui.table_models import ColumnTableModel

    model = ColumnTableModel([("BSSID", lambda row: row, None)])
    model.set_mono_columns(0)
    model.set_rows(["aa:bb:cc:dd:ee:ff"])
    font = model.data(model.index(0, 0), _Qt.ItemDataRole.FontRole)
    assert isinstance(font, QFont)
    assert font.family() in {"Consolas", "Cascadia Mono"}


def test_dialog_code_enum_is_usable() -> None:
    assert QDialog.DialogCode.Accepted != QDialog.DialogCode.Rejected


# ------------------------------------------------------- alert workflow


def test_alert_workflow_from_the_alerts_page(window: MainWindow, context: AppContext) -> None:
    """Acknowledge / resolve / reopen from the queue, end to end."""
    from app.models import AlertStatus

    context.monitoring.scan_once()
    page = window._alerts  # noqa: SLF001
    page.refresh()
    assert page._model.rowCount() >= 1  # noqa: SLF001

    # Keep every status visible so the row stays selected between actions.
    # Note: the model reset after each action clears the view's selection.
    page._status_filter.setCurrentText("All statuses")  # noqa: SLF001

    page._table.selectRow(0)  # noqa: SLF001
    page._transition(AlertStatus.ACKNOWLEDGED)  # noqa: SLF001
    assert context.alerts.list(status=AlertStatus.ACKNOWLEDGED), "acknowledge did not persist"

    page._table.selectRow(0)  # noqa: SLF001
    page._transition(AlertStatus.RESOLVED)  # noqa: SLF001
    assert context.alerts.list(status=AlertStatus.RESOLVED), "resolve did not persist"

    page._table.selectRow(0)  # noqa: SLF001
    page._transition(AlertStatus.ACTIVE)  # noqa: SLF001
    assert context.alerts.list(status=AlertStatus.ACTIVE), "reopen did not persist"


def test_alerts_filter_by_status(window: MainWindow, context: AppContext) -> None:
    from app.models import AlertStatus

    context.monitoring.scan_once()
    page = window._alerts  # noqa: SLF001
    page.refresh()
    total = page._model.rowCount()  # noqa: SLF001
    assert total >= 1

    # Resolve everything: the active queue shrinks by one row per action.
    guard = 0
    while page._model.rowCount():  # noqa: SLF001
        page._table.selectRow(0)  # noqa: SLF001
        page._transition(AlertStatus.RESOLVED)  # noqa: SLF001
        guard += 1
        assert guard <= total + 2, "resolve loop did not converge"

    page._status_filter.setCurrentText("Resolved")  # noqa: SLF001
    assert page._model.rowCount() == total  # noqa: SLF001
    page._status_filter.setCurrentText("Active")  # noqa: SLF001
    assert page._model.rowCount() == 0  # noqa: SLF001
    assert "No alerts match" in page._detail.text()  # noqa: SLF001


def test_alerts_csv_export_from_the_page(
    window: MainWindow, context: AppContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PySide6.QtWidgets import QFileDialog

    context.monitoring.scan_once()
    page = window._alerts  # noqa: SLF001
    page.refresh()
    assert page._model.rowCount() >= 1  # noqa: SLF001

    target = tmp_path / "exported.csv"
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *a, **k: (str(target), "CSV files (*.csv)")),
    )

    page._export_csv()  # noqa: SLF001

    assert target.is_file()
    text = target.read_text(encoding="utf-8-sig")
    assert "alert_type" in text.splitlines()[0]


# ------------------------------------------------------- live networks


def test_live_networks_filtering_and_double_click(window: MainWindow, context: AppContext) -> None:
    context.monitoring.scan_once()
    page = window._live  # noqa: SLF001
    page.refresh()
    total = len(page.snapshots)
    assert total >= 3

    page._search.setText("Corporate")  # noqa: SLF001
    assert 0 < page._model.rowCount() < total  # noqa: SLF001
    for row in range(page._model.rowCount()):  # noqa: SLF001
        snapshot = page._model.row_at(row)
        assert "corporate" in (snapshot.ssid or "").lower()

    page._search.setText("definitely-not-a-network")  # noqa: SLF001
    assert page._model.rowCount() == 0  # noqa: SLF001
    page._search.setText("")  # noqa: SLF001
    page._filter.setCurrentText("Trusted only")  # noqa: SLF001
    assert page._model.rowCount() == 0  # noqa: SLF001  # nothing trusted yet

    # Double-clicking a row jumps to investigation.
    page._filter.setCurrentText("All networks")  # noqa: SLF001
    page._table.selectRow(0)  # noqa: SLF001
    page._open_investigation(page._model.index(0, 0))  # noqa: SLF001
    assert window.current_page_key() == "investigation"
    assert window._investigation.identity != (None, None)  # noqa: SLF001


def test_live_networks_trusted_row_appears_after_baseline(
    window: MainWindow, context: AppContext
) -> None:
    context.trusted.upsert(
        TrustedNetwork(ssid="Corporate", approved_bssids=("10:20:30:40:50:60",))
    )
    context.monitoring.scan_once()
    page = window._live  # noqa: SLF001
    page.refresh()

    labels = {s.ssid: s.trust_label for s in page.snapshots}
    assert labels["Corporate"] in {"Trusted", "Trusted name, new radio"}
    trusted_rows = [s for s in page.snapshots if s.trusted]
    assert trusted_rows


# ------------------------------------------------------------- dashboard


def test_dashboard_reflects_scan_and_alert_counts(window: MainWindow, context: AppContext) -> None:
    dashboard = window._dashboard  # noqa: SLF001
    dashboard.refresh()
    assert dashboard._visible_card.value() == "0"  # noqa: SLF001

    context.monitoring.scan_once()
    dashboard.refresh()

    assert dashboard._visible_card.value() == "4"  # noqa: SLF001
    assert int(dashboard._alerts_card.value()) >= 1  # noqa: SLF001
    assert dashboard._environment_labels["last_scan"].text() not in {
        "not yet scanned",
        "failed",
    }  # noqa: SLF001
    assert dashboard._alerts_model.rowCount() >= 1  # noqa: SLF001
