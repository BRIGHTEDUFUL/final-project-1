"""Investigation: full reasoning for one identity, with history charts.

Every score must be explainable, so this screen shows the same evidence the
engine used: baseline, findings, signal history, security observations and
alert history for the selected SSID/BSSID pair.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.context import AppContext
from app.models import NetworkObservation, TrustedNetwork
from app.services.views import severity_name
from app.ui.pages.base import Page
from app.ui.theme import ACCENT, LINE, SEVERITY_COLORS, TEXT_LOW, TEXT_MID
from app.ui.widgets import SeverityBadge

logger = logging.getLogger(__name__)

__all__ = ["InvestigationPage"]

#: Facts that are identifiers or timestamps (rendered in monospace).
_MONO_FACTS = frozenset({"first_seen", "last_seen", "baseline"})

#: Chart colours: the tab-pane surface, the hairline and the signal accent.
CHART_SURFACE = "#11171e"

try:  # Matplotlib is optional at import time so headless tools keep working.
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as _FigureCanvas
    from matplotlib.figure import Figure as _Figure

    _HAS_MATPLOTLIB = True
except Exception:  # pragma: no cover - depends on the host environment
    _HAS_MATPLOTLIB = False
    logger.debug("matplotlib Qt backend unavailable; charts are disabled")


class InvestigationPage(Page):
    """Drill-down screen for a single SSID/BSSID identity."""

    #: Emitted when the user asks to trust the current SSID.
    request_trust = Signal(object)

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Investigation",
            "Evidence, history and reasoning for one network identity.",
            parent,
        )
        self._context = context
        self._ssid: str | None = None
        self._bssid: str | None = None

        # ---- identity header --------------------------------------------
        header = QHBoxLayout()
        header.setSpacing(12)
        self._title = QLabel("No identity selected")
        self._title.setObjectName("identityTitle")
        self._score = QLabel("")
        self._score.setObjectName("scoreLabel")
        self._badge = SeverityBadge("")
        header.addWidget(self._title, 1)
        header.addWidget(self._score)
        header.addWidget(self._badge)

        self._trust_button = QPushButton("Add to trusted networks")
        self._trust_button.setObjectName("primaryButton")
        self._trust_button.clicked.connect(self._emit_trust)
        self._trust_button.setEnabled(False)
        header.addWidget(self._trust_button)
        self.body.addLayout(header)

        # ---- facts ------------------------------------------------------
        facts_box = QGroupBox("Current facts")
        facts = QGridLayout(facts_box)
        facts.setHorizontalSpacing(20)
        self._facts: dict[str, QLabel] = {}
        fact_keys = (
            ("signal", "Signal"),
            ("security", "Security"),
            ("channel", "Channel"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
            ("occurrences", "Alert occurrences"),
            ("trust", "Trust status"),
            ("baseline", "Baseline"),
        )
        for index, (key, caption) in enumerate(fact_keys):
            row, column = divmod(index, 2)
            caption_label = QLabel(caption)
            caption_label.setObjectName("fieldCaption")
            value = QLabel("\u2014")
            # Identifiers and timestamps align in monospace.
            value.setObjectName("fieldMono" if key in _MONO_FACTS else "fieldValue")
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            facts.addWidget(caption_label, row, column * 2)
            facts.addWidget(value, row, column * 2 + 1)
            self._facts[key] = value
        facts.setColumnStretch(1, 1)
        facts.setColumnStretch(3, 1)
        self.body.addWidget(facts_box)

        # ---- tabs -------------------------------------------------------
        tabs = QTabWidget()

        self._reasons = QTextEdit()
        self._reasons.setReadOnly(True)
        self._reasons.setPlaceholderText("No findings recorded for this identity yet.")
        tabs.addTab(self._reasons, "Reasons")

        self._security_log = QTextEdit()
        self._security_log.setReadOnly(True)
        self._security_log.setPlaceholderText("No security observations recorded.")
        tabs.addTab(self._security_log, "Security observations")

        self._bssid_log = QTextEdit()
        self._bssid_log.setReadOnly(True)
        self._bssid_log.setPlaceholderText("No BSSID history recorded.")
        tabs.addTab(self._bssid_log, "BSSID history")

        self._alert_log = QTextEdit()
        self._alert_log.setReadOnly(True)
        self._alert_log.setPlaceholderText("No alerts for this identity.")
        tabs.addTab(self._alert_log, "Alert history")

        if _HAS_MATPLOTLIB:
            self._chart_host = QWidget()
            chart_layout = QVBoxLayout(self._chart_host)
            chart_layout.setContentsMargins(0, 6, 0, 0)
            self._figure = _Figure(figsize=(6, 2.4), tight_layout=True)
            self._figure.patch.set_facecolor(CHART_SURFACE)
            self._canvas = _FigureCanvas(self._figure)
            chart_layout.addWidget(self._canvas)
            tabs.addTab(self._chart_host, "Signal history")
        else:
            self._canvas = None

        self.body.addWidget(tabs, 1)

    # ----------------------------------------------------------------- data

    def show_identity(self, ssid: str | None, bssid: str | None) -> None:
        """Load everything known about ``(ssid, bssid)``."""
        self._ssid = ssid
        self._bssid = bssid
        self.refresh()

    @property
    def identity(self) -> tuple[str | None, str | None]:
        """Currently displayed identity."""
        return (self._ssid, self._bssid)

    def refresh(self) -> None:
        """Reload the identity details from storage."""
        if self._ssid is None and self._bssid is None:
            self._title.setText("No identity selected")
            return

        context = self._context
        label = self._ssid or "<hidden SSID>"
        radio = f"  \u00b7  {self._bssid}" if self._bssid else ""
        self._title.setText(f"{label}{radio}")

        if self._bssid:
            observations = context.observations.for_bssid(self._bssid, limit=500)
        else:
            observations = context.observations.for_ssid(self._ssid or "", limit=500)
        observations = list(observations)

        profile = context.trusted.get_by_ssid(self._ssid) if self._ssid else None
        alerts = context.alerts.list(ssid=self._ssid, bssid=self._bssid, limit=50)
        scores = context.scores.history(ssid=self._ssid, bssid=self._bssid, limit=100)

        latest_score = scores[0] if scores else None
        score_value = int(latest_score["score"]) if latest_score else None
        severity = str(latest_score["severity"]) if latest_score else None

        self._score.setText(f"score {score_value}" if score_value is not None else "")
        # Colour only: size and weight live in the #scoreLabel theme rule.
        self._score.setStyleSheet(
            f"color: {SEVERITY_COLORS.get(severity or '', TEXT_MID)};"
        )
        self._badge.set_text(severity or "")

        current = observations[0] if observations else None
        self._facts["signal"].setText(
            f"{current.signal_strength}%" if current and current.signal_strength is not None else "\u2014"
        )
        self._facts["security"].setText(current.security if current and current.security else "\u2014")
        self._facts["channel"].setText(
            str(current.channel) if current and current.channel is not None else "\u2014"
        )

        if observations:
            oldest = min(observations, key=lambda o: o.observed_at)
            newest = max(observations, key=lambda o: o.observed_at)
            self._facts["first_seen"].setText(oldest.observed_at.strftime("%Y-%m-%d %H:%M:%S"))
            self._facts["last_seen"].setText(newest.observed_at.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            self._facts["first_seen"].setText("\u2014")
            self._facts["last_seen"].setText("\u2014")

        occurrences = sum(a.occurrence_count for a in alerts)
        self._facts["occurrences"].setText(str(occurrences) if occurrences else "0")

        self._facts["trust"].setText(self._trust_label(profile))
        self._facts["baseline"].setText(
            ", ".join(profile.approved_bssids) if profile and profile.approved_bssids else "\u2014"
        )
        self._trust_button.setEnabled(self._ssid is not None)

        self._reasons.setPlainText(self._build_reasons(latest_score, alerts))
        self._security_log.setPlainText(self._build_security_log(observations))
        self._bssid_log.setPlainText(self._build_bssid_log())
        self._alert_log.setPlainText(self._build_alert_log(alerts))
        if self._canvas is not None:
            self._draw_signal_history(observations)

    # ------------------------------------------------------------ builders

    def _trust_label(self, profile: TrustedNetwork | None) -> str:
        if profile is None:
            return "Not in the trusted baseline"
        if profile.knows_bssids:
            approved = profile.approves(self._bssid) if self._bssid else False
            return "Trusted (approved radio)" if approved else "Trusted name \u2014 radio not approved"
        return "Trusted name (no BSSIDs registered yet)"

    def _build_reasons(self, latest_score: dict | None, alerts: list) -> str:
        lines: list[str] = []
        if latest_score:
            lines.append(f"Latest score: {latest_score['score']} ({latest_score['severity']})")
            lines.append(f"Recorded at: {latest_score['created_at']}")
            lines.append("")
            for reason in latest_score.get("reasons") or []:
                lines.append(f"\u2022 {reason}")
        if alerts:
            lines.append("")
            lines.append("Alert evidence:")
            for alert in alerts[:10]:
                lines.append(
                    f"\u2022 [{alert.severity.value if alert.severity else '?'}] "
                    f"{alert.alert_type.value} \u2014 {alert.evidence}"
                )
        return "\n".join(lines) if lines else "No findings have been recorded for this identity."

    def _build_security_log(self, observations: list[NetworkObservation]) -> str:
        if not observations:
            return "No security observations recorded."
        entries: list[str] = []
        seen: set[str] = set()
        for observation in sorted(observations, key=lambda o: o.observed_at, reverse=True):
            label = observation.security or "(not reported)"
            if label in seen:
                continue
            seen.add(label)
            entries.append(f"{observation.observed_at.strftime('%Y-%m-%d %H:%M:%S')}  \u2014  {label}")
        return "\n".join(entries)

    def _build_bssid_log(self) -> str:
        context = self._context
        if self._ssid and not self._bssid:
            rows = context.observations.for_ssid(self._ssid, limit=500)
            grouped: dict[str, int] = {}
            latest: dict[str, str] = {}
            for observation in rows:
                key = observation.bssid or "(none)"
                grouped[key] = grouped.get(key, 0) + 1
                latest[key] = observation.observed_at.strftime("%Y-%m-%d %H:%M:%S")
            if not grouped:
                return "No BSSID history recorded."
            return "\n".join(
                f"{bssid}  \u2014  seen {count}x, last {latest[bssid]}"
                for bssid, count in sorted(grouped.items())
            )
        if self._bssid:
            rows = context.observations.for_bssid(self._bssid, limit=500)
            names: dict[str, str] = {}
            for observation in rows:
                names[observation.ssid or "(hidden)"] = observation.observed_at.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            if not names:
                return "No SSID history recorded for this radio."
            return "\n".join(
                f"{name}  \u2014  last {stamp}" for name, stamp in sorted(names.items())
            )
        return "No BSSID history recorded."

    def _build_alert_log(self, alerts: list) -> str:
        if not alerts:
            return "No alerts for this identity."
        lines = []
        for alert in alerts:
            severity = severity_name(alert.severity) or "?"
            lines.append(
                f"{alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}  \u2014  "
                f"[{severity}] {alert.alert_type.value} score={alert.risk_score} "
                f"status={alert.status.value} seen {alert.occurrence_count}x"
            )
            lines.append(f"    {alert.evidence}")
        return "\n".join(lines)

    def _draw_signal_history(self, observations: list[NetworkObservation]) -> None:
        if self._canvas is None:
            return
        self._figure.clear()
        axis = self._figure.add_subplot(111)
        axis.set_facecolor(CHART_SURFACE)
        for spine in axis.spines.values():
            spine.set_color(LINE)
        axis.tick_params(colors=TEXT_MID, labelsize=8)

        points = [
            observation
            for observation in observations
            if observation.signal_strength is not None
        ]
        if points:
            points.sort(key=lambda o: o.observed_at)
            xs = [observation.observed_at for observation in points]
            ys = [observation.signal_strength for observation in points]
            axis.plot(xs, ys, color=ACCENT, linewidth=1.6, marker="o", markersize=3)
            axis.set_ylim(0, 105)
            axis.set_ylabel("Signal %", color=TEXT_MID, fontsize=9)
            axis.grid(True, color=LINE, linewidth=0.7)
        else:
            axis.text(
                0.5,
                0.5,
                "No signal readings recorded",
                color=TEXT_LOW,
                ha="center",
                va="center",
                transform=axis.transAxes,
            )
        self._figure.autofmt_xdate(rotation=20)
        self._canvas.draw_idle()

    # ------------------------------------------------------------ interaction

    def _emit_trust(self) -> None:
        if self._ssid is not None:
            self.request_trust.emit(self._ssid)
