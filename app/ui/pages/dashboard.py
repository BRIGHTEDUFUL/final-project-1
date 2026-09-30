"""Dashboard: environment overview, health signals and the newest alerts."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QLabel,
    QWidget,
)

from app.core.context import AppContext
from app.ui.pages.base import Page, section_title
from app.ui.table_models import ColumnTableModel
from app.ui.theme import SEVERITY_COLORS
from app.ui.widgets import StatCard, stat_strip, styled_table

__all__ = ["DashboardPage"]

#: Environment fields whose values are identifiers or timestamps.
_MONO_FIELDS = frozenset({"bssid", "last_scan"})


def _severity_of(alert: object) -> str | None:
    severity = getattr(alert, "severity", None)
    return severity.value if severity is not None else None


class DashboardPage(Page):
    """First screen: what is happening right now."""

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Dashboard",
            "Live overview of the radio environment and current risk posture.",
            parent,
        )
        self._context = context

        # ---- instrument strip: one panel, four readouts, hairline dividers ----
        cards = (
            StatCard("Networks in last scan"),
            StatCard("Trusted networks"),
            StatCard("Open alerts"),
            StatCard("Critical alerts"),
        )
        self._visible_card, self._trusted_card, self._alerts_card, self._critical_card = cards
        self.body.addWidget(stat_strip(cards))

        # ---- environment ------------------------------------------------
        environment = QGroupBox("Current environment")
        environment_layout = QGridLayout(environment)
        environment_layout.setHorizontalSpacing(18)
        environment_layout.setVerticalSpacing(8)
        self._environment_labels: dict[str, QLabel] = {}
        fields = (
            ("interface", "Interface"),
            ("ssid", "Connected SSID"),
            ("bssid", "Access point"),
            ("channel", "Channel"),
            ("authentication", "Security"),
            ("signal", "Signal"),
            ("last_scan", "Last scan"),
            ("history", "BSSIDs in history"),
        )
        for row, (key, caption) in enumerate(fields):
            label_caption = QLabel(caption)
            label_caption.setObjectName("fieldCaption")
            value = QLabel("\u2014")
            # Identifiers and timestamps are set in monospace so they align.
            value.setObjectName("fieldMono" if key in _MONO_FIELDS else "fieldValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid_row = row // 2
            grid_col = row % 2
            environment_layout.addWidget(label_caption, grid_row, grid_col * 2)
            environment_layout.addWidget(value, grid_row, grid_col * 2 + 1)
            self._environment_labels[key] = value
        environment_layout.setColumnStretch(1, 1)
        environment_layout.setColumnStretch(3, 1)
        self.body.addWidget(environment)

        # ---- recent alerts ---------------------------------------------
        self.body.addWidget(section_title("Most recent alerts"))
        self._alerts_model = ColumnTableModel(
            [
                ("Severity", lambda a: a.severity.value if a.severity else None, None),
                ("Score", lambda a: a.risk_score, None),
                ("Type", lambda a: a.alert_type.value.replace("_", " "), None),
                ("SSID", lambda a: a.ssid, None),
                ("BSSID", lambda a: a.bssid, None),
                (
                    "Evidence",
                    lambda a: "; ".join(a.reasons)[:120],
                    lambda a: a.evidence,
                ),
                ("Status", lambda a: a.status.value, None),
                ("First seen", lambda a: a.first_seen.strftime("%Y-%m-%d %H:%M") if a.first_seen else None, None),
            ]
        )
        self._alerts_model.set_color_column(0, _severity_of)
        self._alerts_model.set_mono_columns(4, 7)
        # Evidence (index 5) is the long text column: let it absorb the slack
        # instead of stretching "First seen" and pushing Status off-screen.
        self._alerts_table = styled_table(self._alerts_model, flex=5)
        self.body.addWidget(self._alerts_table)

        hint = QLabel("Use Investigation for the full reasoning behind any score.")
        hint.setObjectName("hint")
        self.body.addWidget(hint)

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Reload every figure from storage and live services."""
        context = self._context
        counts = context.alert_manager.counts()
        open_total = sum(counts.values())
        critical = counts.get("critical", 0)

        report = context.monitoring.last_report
        if report is not None and report.ok:
            self._visible_card.set_value(report.network_count)
            self._environment_labels["last_scan"].setText(
                report.session.started_at.strftime("%Y-%m-%d %H:%M:%S")
            )
        elif report is not None:
            self._visible_card.set_value(0)
            self._environment_labels["last_scan"].setText("failed")
        else:
            self._visible_card.set_value(0)
            self._environment_labels["last_scan"].setText("not yet scanned")

        self._trusted_card.set_value(context.trusted.count())
        self._alerts_card.set_value(open_total)
        self._critical_card.set_value(critical)
        self._critical_card.set_color(SEVERITY_COLORS.get("critical") if critical else None)
        self._alerts_card.set_color(
            SEVERITY_COLORS.get("high") if counts.get("high", 0) else None
        )

        interface = context.pipeline.last_interface
        if interface is not None:
            self._environment_labels["interface"].setText(interface.name or "\u2014")
            self._environment_labels["ssid"].setText(interface.ssid or "\u2014")
            self._environment_labels["bssid"].setText(interface.bssid or "\u2014")
            self._environment_labels["channel"].setText(
                str(interface.channel) if interface.channel is not None else "\u2014"
            )
            self._environment_labels["authentication"].setText(
                interface.authentication or "\u2014"
            )
            self._environment_labels["signal"].setText(
                f"{interface.signal}%" if interface.signal is not None else "\u2014"
            )
        self._environment_labels["history"].setText(
            str(context.pipeline.known_bssids_count)
        )

        self._alerts_model.set_rows(context.alert_manager.active(limit=8))
