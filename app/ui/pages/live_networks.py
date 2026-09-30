"""Live networks: every identity seen recently, filterable and sortable."""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QWidget,
)

from app.core.context import AppContext
from app.services.views import NetworkSnapshot, build_snapshots
from app.ui.pages.base import Page
from app.ui.table_models import ColumnTableModel
from app.ui.widgets import styled_table

__all__ = ["LiveNetworksPage"]

_FILTERS = ("All networks", "Unknown only", "Flagged only", "Trusted only")


class LiveNetworksPage(Page):
    """Sortable table of current wireless networks."""

    #: Emitted when the user double-clicks a row (ssid, bssid).
    open_investigation = Signal(object, object)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Live networks",
            "One row per radio currently known to the last scan. "
            "Double-click a row to investigate it.",
            parent,
        )
        self._context = context
        self._snapshots: list[NetworkSnapshot] = []

        # ---- toolbar ----------------------------------------------------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._search = QLineEdit()
        self._search.setObjectName("searchField")
        self._search.setPlaceholderText("Filter by SSID or BSSID\u2026")
        self._search.setClearButtonEnabled(True)
        self._search.setMaximumWidth(320)
        self._search.textChanged.connect(self._apply_filter)

        self._filter = QComboBox()
        self._filter.addItems(_FILTERS)
        self._filter.currentIndexChanged.connect(self._apply_filter)

        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.setObjectName("secondaryButton")
        self._refresh_button.clicked.connect(self.refresh)

        self._count_label = QLabel("0 networks")
        self._count_label.setObjectName("countLabel")

        toolbar.addWidget(self._search, 1)
        toolbar.addWidget(self._filter)
        toolbar.addWidget(self._refresh_button)
        toolbar.addStretch(1)
        toolbar.addWidget(self._count_label)
        self.body.addLayout(toolbar)

        # ---- table ------------------------------------------------------
        self._model = ColumnTableModel(
            [
                ("SSID", lambda s: s.ssid, None),
                ("BSSID", lambda s: s.bssid, None),
                ("Signal %", lambda s: s.signal_strength, None),
                ("Security", lambda s: s.security, None),
                ("Channel", lambda s: s.channel, None),
                ("Trust", lambda s: s.trust_label, None),
                ("Risk", lambda s: s.score, None),
                ("Severity", lambda s: s.severity, None),
                (
                    "Last seen",
                    lambda s: s.observed_at.strftime("%H:%M:%S") if s.observed_at else None,
                    lambda s: s.observed_at.isoformat() if s.observed_at else None,
                ),
            ]
        )
        self._model.set_color_column(7, lambda snapshot: snapshot.severity)
        self._model.set_mono_columns(1, 8)
        self._table = styled_table(self._model)
        self._table.doubleClicked.connect(self._open_investigation)
        self.body.addWidget(self._table)

        self._empty_hint = QLabel(
            "No networks yet \u2014 start monitoring or press Refresh to scan once."
        )
        self._empty_hint.setObjectName("hint")
        self.body.addWidget(self._empty_hint)

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Rebuild the snapshot from storage."""
        context = self._context
        self._snapshots = build_snapshots(
            observations=context.observations.recent(limit=1000),
            trusted=context.trusted.list(),
            scores=context.scores.latest_scores(limit=1000),
        )
        self._apply_filter()

    def on_scan_report(self, report: object) -> None:
        """Update automatically after each completed scan."""
        self.refresh()

    # --------------------------------------------------------------- filter

    def _apply_filter(self, *_args: object) -> None:
        text = self._search.text().strip().lower()
        mode = self._filter.currentText()
        rows: list[NetworkSnapshot] = []

        for snapshot in self._snapshots:
            if text:
                haystack = f"{snapshot.ssid or ''} {snapshot.bssid or ''}".lower()
                if text not in haystack:
                    continue
            if mode == "Unknown only" and snapshot.trusted:
                continue
            if mode == "Flagged only" and not snapshot.is_suspicious:
                continue
            if mode == "Trusted only" and not snapshot.trusted:
                continue
            rows.append(snapshot)

        # The view sorts via a proxy on the sorted column; ordering here only
        # provides a sensible default (strongest signal first).
        self._model.set_rows(rows)
        self._count_label.setText(f"{len(rows)} network{'s' if len(rows) != 1 else ''}")
        self._empty_hint.setVisible(not rows)

    # ---------------------------------------------------------- interaction

    def _open_investigation(self, index: QModelIndex) -> None:
        snapshot = self._model.row_at(index.row())
        if snapshot is None:
            return
        self.open_investigation.emit(snapshot.ssid, snapshot.bssid)

    @property
    def snapshots(self) -> list[NetworkSnapshot]:
        """Current snapshot rows (exposed for tests)."""
        return list(self._snapshots)
