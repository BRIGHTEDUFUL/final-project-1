"""Alerts: the queue of open findings, with workflow actions and export."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from app.core.context import AppContext
from app.models import AlertStatus, Severity
from app.services.export import ExportError, export_alerts_csv
from app.ui.pages.base import Page
from app.ui.table_models import ColumnTableModel
from app.ui.widgets import styled_table

__all__ = ["AlertsPage"]

_STATUSES = ("Active", "Acknowledged", "Resolved", "All statuses")
_SEVERITIES = ("All severities", "Critical", "High", "Suspicious", "Low")


class AlertsPage(Page):
    """Alert queue with acknowledge/resolve workflow."""

    #: Emitted when the user double-clicks a row (ssid, bssid).
    open_investigation = Signal(object, object)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Alerts",
            "Risk-scored, explainable events. Acknowledge or resolve after review.",
            parent,
        )
        self._context = context

        # ---- toolbar ----------------------------------------------------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._status_filter = QComboBox()
        self._status_filter.addItems(_STATUSES)
        self._status_filter.currentIndexChanged.connect(self._reload)

        self._severity_filter = QComboBox()
        self._severity_filter.addItems(_SEVERITIES)
        self._severity_filter.currentIndexChanged.connect(self._reload)

        self._ack_button = QPushButton("Acknowledge")
        self._ack_button.setObjectName("secondaryButton")
        self._ack_button.clicked.connect(lambda: self._transition(AlertStatus.ACKNOWLEDGED))
        self._resolve_button = QPushButton("Resolve")
        self._resolve_button.setObjectName("secondaryButton")
        self._resolve_button.clicked.connect(lambda: self._transition(AlertStatus.RESOLVED))
        self._reopen_button = QPushButton("Reopen")
        self._reopen_button.setObjectName("secondaryButton")
        self._reopen_button.clicked.connect(lambda: self._transition(AlertStatus.ACTIVE))

        self._export_button = QPushButton("Export CSV\u2026")
        self._export_button.setObjectName("secondaryButton")
        self._export_button.clicked.connect(self._export_csv)

        self._count_label = QLabel("0 alerts")
        self._count_label.setObjectName("countLabel")

        toolbar.addWidget(self._status_filter)
        toolbar.addWidget(self._severity_filter)
        toolbar.addSpacing(12)
        toolbar.addWidget(self._ack_button)
        toolbar.addWidget(self._resolve_button)
        toolbar.addWidget(self._reopen_button)
        toolbar.addStretch(1)
        toolbar.addWidget(self._export_button)
        toolbar.addWidget(self._count_label)
        self.body.addLayout(toolbar)

        # ---- table ------------------------------------------------------
        self._model = ColumnTableModel(
            [
                ("Severity", lambda a: a.severity.value if a.severity else None, None),
                ("Score", lambda a: a.risk_score, None),
                ("Type", lambda a: a.alert_type.value.replace("_", " "), None),
                ("SSID", lambda a: a.ssid, None),
                ("BSSID", lambda a: a.bssid, None),
                ("Status", lambda a: a.status.value, None),
                ("Seen", lambda a: a.occurrence_count, None),
                (
                    "First seen",
                    lambda a: a.first_seen.strftime("%Y-%m-%d %H:%M") if a.first_seen else None,
                    lambda a: a.first_seen.isoformat() if a.first_seen else None,
                ),
                (
                    "Last seen",
                    lambda a: a.last_seen.strftime("%Y-%m-%d %H:%M") if a.last_seen else None,
                    lambda a: a.last_seen.isoformat() if a.last_seen else None,
                ),
                ("Evidence", lambda a: "; ".join(a.reasons)[:160], lambda a: a.evidence),
            ]
        )
        self._model.set_color_column(0, lambda alert: alert.severity.value if alert.severity else None)
        self._model.set_mono_columns(4, 7, 8)
        self._table = styled_table(self._model)
        self._table.doubleClicked.connect(self._open_investigation)
        self.body.addWidget(self._table)

        self._detail = QLabel("Select an alert to see its full evidence here.")
        self._detail.setWordWrap(True)
        self._detail.setObjectName("detailBox")
        self.body.addWidget(self._detail)

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Reload alerts using the active filters."""
        self._reload()

    def on_scan_report(self, report: object) -> None:
        """Refresh automatically after every scan."""
        self._reload()

    def _filters(self) -> dict:
        filters: dict = {}
        status_text = self._status_filter.currentText()
        if status_text != "All statuses":
            filters["status"] = AlertStatus(status_text.lower())
        severity_text = self._severity_filter.currentText()
        if severity_text != "All severities":
            filters["severity"] = Severity(severity_text.lower())
        return filters

    def _reload(self, *_args: object) -> None:
        alerts = self._context.alerts.list(**self._filters(), limit=1000)
        self._model.set_rows(alerts)
        self._count_label.setText(f"{len(alerts)} alert{'s' if len(alerts) != 1 else ''}")
        if not alerts:
            self._detail.setText("No alerts match the current filters.")
        self._update_detail()

    def _selected_alert(self) -> object | None:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            return None
        return self._model.row_at(indexes[0].row())

    def _update_detail(self) -> None:
        alert = self._selected_alert()
        if alert is None:
            if self._model.rowCount():
                self._detail.setText("Select an alert to see its full evidence here.")
            return
        severity = alert.severity.value if alert.severity else "?"
        self._detail.setText(
            f"<b>[{severity.capitalize()}] {alert.alert_type.value.replace('_', ' ')} "
            f"\u2014 score {alert.risk_score}</b><br/>"
            f"{alert.ssid or '&lt;hidden&gt;'} [{alert.bssid or 'unknown BSSID'}]"
            f"<br/>{alert.evidence}"
        )

    # ------------------------------------------------------------ actions

    def _transition(self, status: AlertStatus) -> None:
        alert = self._selected_alert()
        if alert is None:
            QMessageBox.information(self, "No alert selected", "Select an alert first.")
            return
        updated = (
            self._context.alert_manager.acknowledge(alert.id)
            if status is AlertStatus.ACKNOWLEDGED
            else (
                self._context.alert_manager.resolve(alert.id)
                if status is AlertStatus.RESOLVED
                else self._context.alert_manager.reopen(alert.id)
            )
        )
        if updated is None:
            QMessageBox.warning(self, "Action failed", "That alert could not be updated.")
            return
        self._reload()

    def _export_csv(self) -> None:
        alerts = self._context.alerts.list(**self._filters(), limit=100000)
        if not alerts:
            QMessageBox.information(self, "Nothing to export", "No alerts match the current filters.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export alerts",
            "rogue_ap_hunter_alerts.csv",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return
        try:
            written = export_alerts_csv(path, alerts)
        except ExportError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export complete", f"Wrote {len(alerts)} alerts to\n{written}")

    def _open_investigation(self, index) -> None:  # noqa: ANN001 - QModelIndex
        alert = self._model.row_at(index.row())
        if alert is None:
            return
        self.open_investigation.emit(alert.ssid, alert.bssid)
