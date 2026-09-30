"""Small reusable widgets shared across screens.

Two rules learned the hard way and encoded here:

* ``QLabel`` inherits ``QFrame``, so any unscoped ``QFrame { ... }`` rule
  inside a widget also styles every label it contains (that is what produced
  boxes-inside-boxes on the dashboard). Frame styling is therefore always
  scoped to an object name.
* ``QWidget`` backgrounds must never be set globally: they paint phantom
  rectangles behind child labels. Backgrounds belong to ``#statStrip``,
  ``QMainWindow`` and friends, defined in :mod:`app.ui.theme`.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.ui.table_models import ColumnTableModel
from app.ui.theme import ACCENT, SEVERITY_COLORS

__all__ = [
    "SignalMark",
    "SeverityBadge",
    "StatCard",
    "StatusLamp",
    "hairline",
    "stat_strip",
    "styled_table",
]


def hairline(orientation: Qt.Orientation = Qt.Orientation.Horizontal) -> QFrame:
    """A one-pixel structural rule (see ``QFrame#rule`` in the stylesheet)."""
    line = QFrame()
    line.setObjectName("rule")
    line.setFrameShape(
        QFrame.Shape.HLine if orientation == Qt.Orientation.Horizontal else QFrame.Shape.VLine
    )
    line.setLineWidth(0)
    return line


class SignalMark(QWidget):
    """Hand-drawn RF mark: an emitter dot with three broadcast arcs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(24, 24)

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: D102 - Qt hook
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(ACCENT)
        origin = QPointF(5.0, 18.0)
        pen = QPen(color, 1.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        for radius in (5.5, 9.5, 13.5):
            painter.drawArc(
                QRectF(origin.x() - radius, origin.y() - radius, 2 * radius, 2 * radius),
                0,
                90 * 16,
            )
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(origin, 2.2, 2.2)


class StatusLamp(QFrame):
    """The live indicator lamp: cyan when active, graphite when idle."""

    def __init__(self, active: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statusDot")
        self.setFixedSize(8, 8)
        self.setProperty("active", active)
        self.setToolTip("Monitoring state")

    def set_active(self, active: bool) -> None:
        """Switch the lamp on or off (repolished so the stylesheet re-reads it)."""
        if bool(self.property("active")) == active:
            return
        self.setProperty("active", active)
        style = self.style()
        style.unpolish(self)
        style.polish(self)
        self.update()

    def is_active(self) -> bool:
        """Whether the lamp is currently on."""
        return bool(self.property("active"))


class StatCard(QFrame):
    """One readout cell of the dashboard instrument strip.

    The cells are transparent; the panel look (background, border, radius)
    belongs to the containing ``QFrame#statStrip`` so the four cells read as
    one continuous instrument divided by hairlines.
    """

    def __init__(self, caption: str, parent: QFrame | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statCell")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(2)

        self._value = QLabel("0")
        self._value.setObjectName("statValue")
        layout.addWidget(self._value)

        self._caption = QLabel(caption)
        self._caption.setObjectName("statCaption")
        layout.addWidget(self._caption)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, value: object) -> None:
        """Update the displayed number/text."""
        self._value.setText(str(value))

    def set_color(self, color: str | None) -> None:
        """Colour the readout (used for alert severities)."""
        # Only the colour is overridden: size and weight stay in the theme.
        self._value.setStyleSheet(f"color: {color};" if color else "")

    def value(self) -> str:
        """Currently displayed value as text."""
        return self._value.text()


def stat_strip(cells: tuple[StatCard, ...]) -> QFrame:
    """Assemble readout cells into one panel divided by hairline rules."""
    strip = QFrame()
    strip.setObjectName("statStrip")
    layout = QHBoxLayout(strip)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    for index, cell in enumerate(cells):
        if index:
            divider = QFrame()
            divider.setObjectName("stripDivider")
            divider.setFixedWidth(1)
            layout.addWidget(divider)
        layout.addWidget(cell, 1)
    return strip


class SeverityBadge(QLabel):
    """Small badge that displays a severity name in its colour."""

    def __init__(self, severity: str = "", parent: QLabel | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setBold(True)
        font.setPointSize(9)
        self.setFont(font)
        self.setMinimumWidth(84)
        self.set_text(severity)

    def set_text(self, severity: str) -> None:
        """Render ``severity`` as a coloured badge (sentence case, not caps)."""
        display = severity.capitalize() if severity else "\u2014"
        self.setText(display)
        color = SEVERITY_COLORS.get(severity.lower())
        if color:
            self.setStyleSheet(
                f"background-color: {color}1f; color: {color};"
                f" border: 1px solid {color}59; border-radius: 4px; padding: 3px 10px;"
            )
        else:
            self.setStyleSheet(
                "background-color: #1a222d; color: #98a4b3;"
                " border: 1px solid #2b3542; border-radius: 4px; padding: 3px 10px;"
            )


def styled_table(model: ColumnTableModel, *, flex: int | None = None) -> QTableView:
    """Build a table view with consistent styling and sorting enabled.

    Columns are sized to their content and ``flex`` (default: the final
    column) is left stretchy, so one long text column absorbs the free space
    while every identifier column keeps exactly the width it needs — the old
    behaviour (fixed 100px columns with only the last stretching) elided
    every timestamp and starved the identifier columns.
    """
    view = QTableView()
    view.setModel(model)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setSortingEnabled(True)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(30)
    header = view.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeToContents)
    # Relying on stretchLastSection() alone leaves the last section stuck at
    # Qt's default 100px (its mode stays ResizeToContents) — a few pixels of
    # permanent horizontal scroll. Setting the mode explicitly is exact.
    if flex is None:
        flex = model.columnCount() - 1
    if 0 <= flex < model.columnCount():
        header.setStretchLastSection(False)
        header.setSectionResizeMode(flex, QHeaderView.Stretch)
    else:
        header.setStretchLastSection(True)
    # Headers sit left-aligned above their cells (Qt centres them by default).
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setHighlightSections(False)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    view.setMinimumHeight(180)
    return view
