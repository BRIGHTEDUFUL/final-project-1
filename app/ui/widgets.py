"""Small reusable widgets shared across screens."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QLabel,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
)

from app.ui.table_models import ColumnTableModel
from app.ui.theme import SEVERITY_COLORS

__all__ = ["StatCard", "SeverityBadge", "styled_table"]


class StatCard(QFrame):
    """Large number with a caption, used on the dashboard."""

    def __init__(self, caption: str, parent: QFrame | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            "QFrame { background-color: #171d26; border: 1px solid #232a34;"
            " border-radius: 10px; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
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
        """Colour the value (used for alert severities)."""
        if color:
            self._value.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: 700;")
        else:
            self._value.setStyleSheet("")

    def value(self) -> str:
        """Currently displayed value as text."""
        return self._value.text()


class SeverityBadge(QLabel):
    """Small pill that displays a severity name in its colour."""

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
        """Render ``severity`` as a coloured badge."""
        display = severity.upper() if severity else "\u2014"
        self.setText(display)
        color = SEVERITY_COLORS.get(severity.lower())
        if color:
            self.setStyleSheet(
                f"background-color: {color}22; color: {color};"
                " border: 1px solid " + color + "66; border-radius: 9px; padding: 3px 8px;"
            )
        else:
            self.setStyleSheet(
                "background-color: #1b2735; color: #8b95a3;"
                " border: 1px solid #2b3543; border-radius: 9px; padding: 3px 8px;"
            )


def styled_table(model: ColumnTableModel) -> QTableView:
    """Build a table view with consistent styling and sorting enabled."""
    view = QTableView()
    view.setModel(model)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setSortingEnabled(True)
    view.verticalHeader().setVisible(False)
    vertical_header = view.verticalHeader()
    vertical_header.setDefaultSectionSize(28)
    view.horizontalHeader().setStretchLastSection(True)
    view.horizontalHeader().setHighlightSections(False)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setMinimumHeight(180)
    return view
