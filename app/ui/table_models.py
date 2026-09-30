"""Reusable Qt table models.

``ColumnTableModel`` turns a list of rows into a sortable, filterable table
with minimal boilerplate: each column is a (header, value getter, optional
tooltip getter) triple. Values are converted with ``str()`` and ``None`` shows
as an em dash so tables never display the word "None".
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt
from PySide6.QtGui import QColor

from app.ui.theme import SEVERITY_COLORS, mono_font

__all__ = ["Column", "ColumnTableModel", "color_for_severity"]

EM_DASH = "\u2014"

Column = tuple[str, Callable[[Any], Any], Callable[[Any], str] | None]


def color_for_severity(value: str | None) -> QColor | None:
    """Return a readable text colour for a severity name, if recognised."""
    if not value:
        return None
    color = SEVERITY_COLORS.get(value.lower())
    return QColor(color) if color else None


class ColumnTableModel(QAbstractTableModel):
    """Table model driven by column definitions."""

    def __init__(
        self,
        columns: Sequence[Column],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._columns = list(columns)
        self._rows: list[Any] = []
        self._color_index = -1
        self._color_getter: Callable[[Any], str | None] | None = None
        self._mono_columns: set[int] = set()

    # ------------------------------------------------------------ configuration

    def set_color_column(self, index: int, getter: Callable[[Any], str | None]) -> None:
        """Colour the cells of column ``index`` with ``getter(row)``'s severity.

        Only the severity column is tinted: identifiers, timestamps and
        evidence stay neutral so a table never turns into a wall of colour.
        """
        self._color_index = index
        self._color_getter = getter

    def set_mono_columns(self, *indices: int) -> None:
        """Render ``indices`` (identifiers, timestamps) in a monospace font."""
        self._mono_columns = {index for index in indices if 0 <= index < len(self._columns)}

    # ----------------------------------------------------------------- data

    def rows(self) -> list[Any]:
        """Current row objects."""
        return list(self._rows)

    def row_at(self, row: int) -> Any | None:
        """Row object at ``row``, or ``None`` when out of range."""
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def set_rows(self, rows: list[Any]) -> None:
        """Replace the data and notify views."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    # --------------------------------------------------------- QAbstractModel

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if parent is not None and parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return len(self._columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self._columns):
            return self._columns[section][0]
        if orientation == Qt.Orientation.Vertical:
            return section + 1
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = self._columns[index.column()]
        getter = column[1]

        if role == Qt.ItemDataRole.DisplayRole:
            value = getter(row)
            if value is None or value == "":
                return EM_DASH
            return value if isinstance(value, (int, float)) else str(value)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            value = getter(row)
            if isinstance(value, (int, float)):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ToolTipRole and column[2] is not None:
            return column[2](row)

        if role == Qt.ItemDataRole.ForegroundRole and self._color_getter is not None:
            # Scope the severity colour to its own column; whole-row tinting
            # made identifiers and timestamps unreadable.
            if index.column() != self._color_index:
                return None
            color = color_for_severity(self._color_getter(row))
            if color is not None:
                return color

        if role == Qt.ItemDataRole.FontRole and index.column() in self._mono_columns:
            return mono_font()

        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        if not 0 <= column < len(self._columns):
            return
        getter = self._columns[column][1]
        self.layoutAboutToBeChanged.emit()

        def key(row: Any) -> tuple[int, Any]:
            value = getter(row)
            if value is None or value == "":
                # Push empty cells to the end regardless of direction.
                return (1, "")
            if isinstance(value, (int, float)):
                return (0, value)
            return (0, str(value).lower())

        self._rows.sort(key=key, reverse=order == Qt.SortOrder.DescendingOrder)
        self.layoutChanged.emit()
