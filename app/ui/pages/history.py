"""History: past scan sessions, stored observations and CSV export."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from app.core.context import AppContext
from app.services.export import ExportError, export_observations_csv
from app.ui.pages.base import Page, section_title
from app.ui.table_models import ColumnTableModel
from app.ui.widgets import styled_table

__all__ = ["HistoryPage"]


class HistoryPage(Page):
    """Read-only timeline of sessions and stored observations."""

    open_investigation = Signal(object, object)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "History",
            "Stored sessions and observations (retention window applies).",
            parent,
        )
        self._context = context

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self._export_button = QPushButton("Export observations CSV\u2026")
        self._export_button.setObjectName("secondaryButton")
        self._export_button.clicked.connect(self._export)
        self._session_label = QLabel("0 sessions")
        self._session_label.setStyleSheet("color: #8b95a3;")
        toolbar.addStretch(1)
        toolbar.addWidget(self._session_label)
        toolbar.addWidget(self._export_button)
        self.body.addLayout(toolbar)

        self.body.addWidget(section_title("Scan sessions"))
        self._session_model = ColumnTableModel(
            [
                ("ID", lambda s: s.id, None),
                (
                    "Started",
                    lambda s: s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                    lambda s: s.started_at.isoformat(),
                ),
                (
                    "Completed",
                    lambda s: s.completed_at.strftime("%Y-%m-%d %H:%M:%S") if s.completed_at else None,
                    None,
                ),
                ("Status", lambda s: s.status.value, None),
                ("Networks", lambda s: s.network_count, None),
            ]
        )
        self._session_table = styled_table(self._session_model)
        self._session_table.setMaximumHeight(220)
        self.body.addWidget(self._session_table)

        self.body.addWidget(section_title("Stored observations"))
        self._obs_model = ColumnTableModel(
            [
                (
                    "Observed",
                    lambda o: o.observed_at.strftime("%Y-%m-%d %H:%M:%S"),
                    lambda o: o.observed_at.isoformat(),
                ),
                ("SSID", lambda o: o.ssid, None),
                ("BSSID", lambda o: o.bssid, None),
                ("Signal %", lambda o: o.signal_strength, None),
                ("Security", lambda o: o.security, None),
                ("Channel", lambda o: o.channel, None),
            ]
        )
        self._obs_table = styled_table(self._obs_model)
        self._obs_table.doubleClicked.connect(self._open_investigation)
        self.body.addWidget(self._obs_table)

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Reload session and observation history."""
        sessions = self._context.sessions.recent(limit=100)
        observations = self._context.observations.recent(limit=500)
        self._session_model.set_rows(sessions)
        self._obs_model.set_rows(observations)
        total = self._context.observations.count()
        self._session_label.setText(
            f"{len(sessions)} session{'s' if len(sessions) != 1 else ''} \u00b7 "
            f"{total} observation{'s' if total != 1 else ''} stored"
        )

    def on_scan_report(self, report: object) -> None:
        """Refresh after each scan so history stays current."""
        self.refresh()

    # ------------------------------------------------------------ actions

    def _export(self) -> None:
        observations = self._context.observations.recent(limit=100000)
        if not observations:
            QMessageBox.information(self, "Nothing to export", "No observations are stored yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export observations",
            "rogue_ap_hunter_observations.csv",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return
        try:
            written = export_observations_csv(path, observations)
        except ExportError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self,
            "Export complete",
            f"Wrote {len(observations)} observations to\n{written}",
        )

    def _open_investigation(self, index) -> None:  # noqa: ANN001 - QModelIndex
        observation = self._obs_model.row_at(index.row())
        if observation is None:
            return
        self.open_investigation.emit(observation.ssid, observation.bssid)
