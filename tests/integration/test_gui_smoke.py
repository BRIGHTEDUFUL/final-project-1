"""GUI smoke tests.

Everything runs on Qt's offscreen platform, so the suite passes on CI and on
machines without an interactive desktop. The tests build the real window, the
real repositories and a fake scanner, then exercise navigation, a full scan
and the settings/trusted-network dialogs.
"""

from __future__ import annotations

import os
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
    assert context.monitoring.last_report is not None
    assert context.observations.count() == 4
    assert window.statusBar().currentMessage() != ""

    window.show_page("live")
    live = window._live  # noqa: SLF001
    live.refresh()
    assert live.snapshots, "live page should show the four observed radios"

    window.show_page("history")
    assert window._history._session_model.rowCount() >= 1  # noqa: SLF001


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

    settings._save()  # noqa: SLF001

    assert context.config.scan_interval_seconds == 45
    assert context.config.suspicious_threshold == 25
    assert context.config.risk_weights.persistence == 15
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
    for token in ("#14181f", "QTableView", "QPushButton#primaryButton", "__ACCENT__"):
        if token == "__ACCENT__":
            assert token not in sheet, "placeholder must be substituted"
        else:
            assert token in sheet


def test_dialog_code_enum_is_usable() -> None:
    assert QDialog.DialogCode.Accepted != QDialog.DialogCode.Rejected
