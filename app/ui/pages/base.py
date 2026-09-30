"""Shared page scaffolding.

Every screen derives from :class:`Page`, which guarantees a consistent header
(title + subtitle + hairline rule) and a ``refresh()`` hook the shell calls
after each scan.
"""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from app.ui.widgets import hairline

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
        self.setObjectName("page")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(28, 24, 28, 24)
        self._layout.setSpacing(10)

        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        self._layout.addWidget(heading)

        if subtitle:
            caption = QLabel(subtitle)
            caption.setObjectName("pageSubtitle")
            caption.setWordWrap(True)
            self._layout.addWidget(caption)

        # The hairline separates header from body so every screen has the
        # same structural anchor.
        self._layout.addWidget(hairline())

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
        """Called after every completed scan; pages with tables reload here."""
        self.refresh()

    def make_scrollable(self) -> None:
        """Move the body into a scroll area.

        Used by screens whose fixed content (forms, group boxes) can exceed
        short windows — without this, the trailing sections are simply
        clipped with no way to reach them.
        """
        scroll = QScrollArea()
        scroll.setObjectName("pageScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setFrameShadow(QScrollArea.Shadow.Plain)

        content = QWidget()
        content.setObjectName("pageScrollContent")
        inner = QVBoxLayout(content)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.setSpacing(10)
        scroll.setWidget(content)

        while self._body.count():
            item = self._body.takeAt(0)
            if item.widget() is not None:
                inner.addWidget(item.widget())
            elif item.layout() is not None:
                inner.addLayout(item.layout())
            del item
        inner.addStretch(1)
        self._body.addWidget(scroll, 1)


def section_title(text: str, parent: QWidget | None = None) -> QLabel:
    """A quiet section heading (see ``QLabel#sectionTitle``)."""
    label = QLabel(text, parent)
    label.setObjectName("sectionTitle")
    return label
