"""Main window: sidebar navigation, monitoring controls and page routing."""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.context import AppContext
from app.ui.bridge import MonitorBridge
from app.ui.pages import (
    AboutPage,
    AlertsPage,
    DashboardPage,
    HistoryPage,
    InvestigationPage,
    LiveNetworksPage,
    SettingsPage,
    TrustedNetworksPage,
)
from app.ui.theme import apply_theme

logger = logging.getLogger(__name__)

__all__ = ["MainWindow", "NAV_ITEMS"]

#: (key, label) for each sidebar entry, in display order.
NAV_ITEMS: tuple[tuple[str, str], ...] = (
    ("dashboard", "Dashboard"),
    ("live", "Live networks"),
    ("investigation", "Investigation"),
    ("alerts", "Alerts"),
    ("trusted", "Trusted networks"),
    ("history", "History"),
    ("settings", "Settings"),
    ("about", "About"),
)


class MainWindow(QMainWindow):
    """Application shell hosting every screen."""

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self._context = context
        self._nav_keys: list[str] = []

        self.setWindowTitle("Rogue AP Hunter")
        self.resize(1220, 800)
        self.setMinimumSize(980, 640)

        # ---- central layout: sidebar | content ---------------------------
        central = QWidget()
        central_layout = QHBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(208)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(4)

        brand = QLabel("Rogue AP Hunter")
        brand.setStyleSheet(
            "font-size: 15px; font-weight: 700; color: #f2f5f9; padding: 4px 6px 12px 6px;"
        )
        sidebar_layout.addWidget(brand)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}
        for index, (key, label) in enumerate(NAV_ITEMS):
            button = QPushButton(label)
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            self._nav_group.addButton(button, index)
            self._nav_buttons[key] = button
            self._nav_keys.append(key)
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch(1)

        # monitoring controls pinned to the bottom of the sidebar
        self._monitor_button = QPushButton("Start monitoring")
        self._monitor_button.setObjectName("primaryButton")
        self._monitor_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._monitor_button.clicked.connect(self.toggle_monitoring)
        sidebar_layout.addWidget(self._monitor_button)

        self._scan_once_button = QPushButton("Scan once")
        self._scan_once_button.setObjectName("secondaryButton")
        self._scan_once_button.clicked.connect(self.scan_once)
        sidebar_layout.addWidget(self._scan_once_button)

        self._monitor_state = QLabel("Monitoring is off")
        self._monitor_state.setWordWrap(True)
        self._monitor_state.setStyleSheet("color: #6b7482; font-size: 11px; padding: 4px;")
        sidebar_layout.addWidget(self._monitor_state)

        central_layout.addWidget(sidebar)

        # ---- pages -------------------------------------------------------
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("QStackedWidget { background-color: #14181f; }")

        self._dashboard = DashboardPage(context)
        self._live = LiveNetworksPage(context)
        self._investigation = InvestigationPage(context)
        self._alerts = AlertsPage(context)
        self._trusted = TrustedNetworksPage(context)
        self._history = HistoryPage(context)
        self._settings = SettingsPage(context)
        self._about = AboutPage()

        self._pages: dict[str, QWidget] = {
            "dashboard": self._dashboard,
            "live": self._live,
            "investigation": self._investigation,
            "alerts": self._alerts,
            "trusted": self._trusted,
            "history": self._history,
            "settings": self._settings,
            "about": self._about,
        }
        for key in self._nav_keys:
            self._stack.addWidget(self._pages[key])

        central_layout.addWidget(self._stack, 1)
        self.setCentralWidget(central)

        # ---- status bar --------------------------------------------------
        status = self.statusBar()
        status.showMessage("Ready \u00b7 monitoring is off")
        self._alert_indicator = QLabel("0 open alerts")
        self._alert_indicator.setStyleSheet("color: #8b95a3; padding-right: 12px;")
        status.addPermanentWidget(self._alert_indicator)

        # ---- wiring ------------------------------------------------------
        for key, button in self._nav_buttons.items():
            button.clicked.connect(lambda _checked=False, k=key: self.show_page(k))

        self._bridge = MonitorBridge(self)
        self._bridge.report_ready.connect(self._on_report)
        self._bridge.error_raised.connect(self._on_error)
        context.set_callbacks(
            on_report=self._bridge.emit_report,
            on_error=self._bridge.emit_error,
        )

        self._live.open_investigation.connect(self.open_investigation)
        self._alerts.open_investigation.connect(self.open_investigation)
        self._history.open_investigation.connect(self.open_investigation)
        self._investigation.request_trust.connect(self._trust_ssid)
        self._trusted.changed.connect(self._refresh_current)

        for sequence, key in (
            ("Ctrl+1", "dashboard"),
            ("Ctrl+2", "live"),
            ("Ctrl+3", "investigation"),
            ("Ctrl+4", "alerts"),
        ):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(lambda k=key: self.show_page(k))
        refresh_shortcut = QShortcut(QKeySequence("F5"), self)
        refresh_shortcut.activated.connect(self._refresh_current)

        self.show_page("dashboard")
        self._update_alert_indicator(context.alert_manager.counts())

    # ----------------------------------------------------------- navigation

    def show_page(self, key: str) -> None:
        """Navigate to the page identified by ``key``."""
        page = self._pages.get(key)
        if page is None:
            logger.warning("unknown page requested: %s", key)
            return
        self._stack.setCurrentWidget(page)
        for nav_key, button in self._nav_buttons.items():
            button.setChecked(nav_key == key)
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    def current_page_key(self) -> str:
        """Key of the page currently displayed."""
        widget = self._stack.currentWidget()
        for key, page in self._pages.items():
            if page is widget:
                return key
        return "dashboard"

    def _switch_by_index(self, index: int) -> None:
        if 0 <= index < len(self._nav_keys):
            self.show_page(self._nav_keys[index])

    def _refresh_current(self) -> None:
        page = self._stack.currentWidget()
        refresh = getattr(page, "refresh", None)
        if callable(refresh):
            refresh()

    # --------------------------------------------------------- monitoring

    @Slot()
    def toggle_monitoring(self) -> None:
        """Start or stop the background monitoring loop."""
        monitoring = self._context.monitoring
        if monitoring.is_running:
            stopped = monitoring.stop()
            self._set_monitor_state(running=False, detail="" if stopped else "stopping\u2026")
            self.statusBar().showMessage("Monitoring stopped", 5000)
            return
        if monitoring.start():
            self._set_monitor_state(running=True)
            self.statusBar().showMessage(
                f"Monitoring started (every {monitoring.interval_seconds}s)", 5000
            )
        else:
            self.statusBar().showMessage("Monitoring could not start", 5000)

    @Slot()
    def scan_once(self) -> None:
        """Run a single scan immediately (blocking, but short)."""
        self._scan_once_button.setEnabled(False)
        try:
            report = self._context.monitoring.scan_once()
        finally:
            self._scan_once_button.setEnabled(True)
        if report.ok:
            self.statusBar().showMessage(report.summary(), 8000)
        else:
            self.statusBar().showMessage(f"Scan failed: {report.error}", 10000)

    def _set_monitor_state(self, running: bool, detail: str = "") -> None:
        self._monitor_button.setText("Stop monitoring" if running else "Start monitoring")
        self._monitor_state.setText(
            ("Monitoring is on" if running else "Monitoring is off") + (f" \u00b7 {detail}" if detail else "")
        )

    # ------------------------------------------------------------- events

    @Slot(object)
    def _on_report(self, report: object) -> None:
        """Handle a completed scan on the GUI thread."""
        counts = self._context.alert_manager.counts()
        self._update_alert_indicator(counts)

        if report.ok:  # type: ignore[attr-defined]
            summary = report.summary()  # type: ignore[attr-defined]
            self.statusBar().showMessage(summary, 8000)
        else:
            self.statusBar().showMessage(f"Scan failed: {report.error}", 10000)  # type: ignore[attr-defined]

        page = self._stack.currentWidget()
        handler = getattr(page, "on_scan_report", None)
        if callable(handler):
            handler(report)
        else:
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                refresh()

    @Slot(str)
    def _on_error(self, message: str) -> None:
        """Show a scan failure without interrupting the user."""
        self.statusBar().showMessage(f"Scan failed: {message}", 10000)
        self._monitor_state.setText(f"Monitoring is on \u00b7 issue: {message[:80]}")

    def _update_alert_indicator(self, counts: dict[str, int]) -> None:
        total = sum(counts.values())
        critical = counts.get("critical", 0)
        label = f"{total} open alert{'s' if total != 1 else ''}"
        if critical:
            label += f" \u00b7 {critical} critical"
        self._alert_indicator.setText(label)
        color = "#e04f4f" if critical else ("#e0a63a" if total else "#8b95a3")
        self._alert_indicator.setStyleSheet(f"color: {color}; padding-right: 12px;")

    @Slot(object)
    def open_investigation(self, ssid: object, bssid: object) -> None:
        """Jump to the investigation screen for one identity."""
        self._investigation.show_identity(ssid, bssid)  # type: ignore[arg-type]
        self.show_page("investigation")

    @Slot(object)
    def _trust_ssid(self, ssid: object) -> None:
        """Pre-fill the trusted-network dialog from the investigation screen."""
        from app.ui.pages.trusted_networks import TrustedNetworkDialog

        existing = self._context.trusted.get_by_ssid(str(ssid)) if ssid else None
        dialog = TrustedNetworkDialog(existing, parent=self)
        if existing is None and ssid:
            dialog.prefill_ssid(str(ssid))
        if dialog.exec() == QDialog.DialogCode.Accepted:
            profile = dialog.profile()
            if profile is not None:
                self._context.trusted.upsert(profile)
                self._trusted.refresh()
                self.statusBar().showMessage(f"'{profile.ssid}' added to the baseline", 6000)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Stop background work before the window disappears."""
        try:
            self._context.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("context did not close cleanly")
        event.accept()


def build_window(context: AppContext) -> MainWindow:
    """Create the main window (theme is applied by the caller)."""
    return MainWindow(context)


def run_app(context: AppContext) -> int:
    """Show the window and run the Qt event loop; return a process exit code."""
    from PySide6.QtWidgets import QApplication

    application = QApplication.instance()
    created = False
    if application is None:
        application = QApplication([])
        created = True

    apply_theme(application)  # type: ignore[arg-type]
    window = MainWindow(context)
    window.show()

    if created:
        exit_code = application.exec()
    else:  # pragma: no cover - embedded/test usage
        exit_code = 0

    context.close()
    logger.info("application exited with code %s", exit_code)
    return exit_code
