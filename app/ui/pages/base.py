"""Shared page scaffolding.

Every screen derives from :class:`Page`, which guarantees a consistent header
(title + subtitle) and a ``refresh()`` hook the shell calls after each scan.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

__all__ = ["Page", "section_title"]


class Page(QWidget):
    """Base class for navigation pages."""

    def __init__(
        self,
        title: str,
        subtitle: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(24, 20, 24, 20)
        self._layout.setSpacing(12)

        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        self._layout.addWidget(heading)

        if subtitle:
            caption = QLabel(subtitle)
            caption.setObjectName("statCaption")
            caption.setWordWrap(True)
            caption.setStyleSheet("color: #8b95a3; font-size: 13px;")
            self._layout.addWidget(caption)

        self._body = QVBoxLayout()
        self._body.setSpacing(10)
        self._layout.addLayout(self._body, 1)

    # ------------------------------------------------------------- accessors

    @property
    def body(self) -> QVBoxLayout:
        """Layout widgets should be added to (below the header)."""
        return self._body

    # ---------------------------------------------------------------- hooks

    def refresh(self) -> None:
        """Called when the page becomes visible or a scan completes."""

    def on_scan_report(self, report: object) -> None:
        """Called for every completed scan while monitoring runs."""


def section_title(text: str) -> QLabel:
    """Create a small section heading used inside pages."""
    label = QLabel(text)
    label.setStyleSheet(
        "font-size: 14px; font-weight: 600; color: #c7cfda; margin-top: 8px;"
    )
    label.setAlignment(Qt.AlignmentFlag.AlignLeft)
    return label
