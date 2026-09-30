"""Visual theme: the instrument-panel design system shared by every screen.

Design concept
--------------
The interface is modelled on lab test equipment (a spectrum analyser front
panel): a graphite housing, panels divided by etched hairlines, a single live
indicator lamp, readouts in large tabular numerals and radio identifiers set
in monospace.

Rules the rest of the UI follows:

* **Colour means state.** Signal cyan marks interaction (active navigation,
  focus, selection, the primary action, the live lamp); the severity palette
  is reserved for risk. Everything else is graphite and hairlines.
* **Structure comes from hairlines**, never shadows or gradients.
* **Prose is Segoe UI, identifiers are monospace** (BSSIDs, baselines).
* **Sentence case throughout** — no all-caps labels.

Implementation note
-------------------
The stylesheet deliberately avoids a global ``QWidget { background }`` rule:
that rule paints phantom boxes behind every child label (a QLabel inherits
QFrame, so frame rules also bleed into labels). Backgrounds are always scoped
to an object name (``#panel``, ``#statStrip``…) or to a container class
(``QMainWindow``, ``QDialog``).
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

__all__ = [
    "ACCENT",
    "CRITICAL_COLOR",
    "HIGH_COLOR",
    "LINE",
    "LOW_COLOR",
    "PANEL",
    "RAISED",
    "SEVERITY_COLORS",
    "SIGNAL",
    "SUSPICIOUS_COLOR",
    "TEXT_HI",
    "TEXT_LOW",
    "TEXT_MID",
    "apply_theme",
    "mono_font",
    "stylesheet",
]

# --------------------------------------------------------------------------- color

#: Interaction accent: navigation markers, focus, selection, the live lamp.
ACCENT = "#3ab7c9"
SIGNAL = ACCENT

GRAPHITE = "#0f141a"  # window background (the housing)
PANEL = "#141a22"  # panel / table header surface
RAISED = "#1a222d"  # hover and secondary-button surface
LINE = "#232c38"  # every hairline

TEXT_HI = "#e9eef4"  # titles, values
TEXT_MID = "#98a4b3"  # labels, secondary text
TEXT_LOW = "#6b7683"  # hints, disabled

# Severity: risk state only. Kept apart from the accent on purpose.
LOW_COLOR = "#57b87d"
SUSPICIOUS_COLOR = "#e3b23f"
HIGH_COLOR = "#f08a3e"
CRITICAL_COLOR = "#f0554f"

SEVERITY_COLORS = {
    "low": LOW_COLOR,
    "suspicious": SUSPICIOUS_COLOR,
    "high": HIGH_COLOR,
    "critical": CRITICAL_COLOR,
}

# Families. The stylesheet may only name fonts that exist on every Windows
# install; the application font is upgraded in apply_theme() when the OS has
# a nicer alternative (Segoe UI Variable / Cascadia Mono).
UI_FALLBACK = "Segoe UI"
MONO_FALLBACK = "Consolas"
_MONO_FAMILY = MONO_FALLBACK


def resolve_families() -> tuple[str, str]:
    """Return ``(ui, mono)`` families actually present on this machine."""
    # QFontDatabase.hasFamily is callable on the class itself in Qt >= 6.9
    # (constructing a QFontDatabase is deprecated).
    ui = "Segoe UI Variable" if QFontDatabase.hasFamily("Segoe UI Variable") else UI_FALLBACK
    mono = "Cascadia Mono" if QFontDatabase.hasFamily("Cascadia Mono") else MONO_FALLBACK
    return ui, mono


def mono_font(point_size: int = 0, *, bold: bool = False) -> QFont:
    """A monospace font for identifiers (cached: called once per table cell)."""
    font = QFont(_MONO_FAMILY)
    if point_size:
        font.setPointSize(point_size)
    font.setBold(bold)
    return font


# -------------------------------------------------------------------- stylesheet

STYLESHEET = """
/* ---------------------------------------------------------------- structure */
QMainWindow {
    background-color: #0f141a;
}
QDialog, QMessageBox {
    background-color: #141a22;
}
QWidget#page {
    background-color: #0f141a;
}
QFrame#sidebar {
    background-color: #0c1116;
    border-right: 1px solid #232c38;
}
QFrame#rule {
    background-color: #232c38;
    min-height: 1px;
    max-height: 1px;
    border: none;
}
QFrame#stripDivider {
    background-color: #232c38;
    min-width: 1px;
    max-width: 1px;
    border: none;
}
QFrame#statusDot {
    background-color: #4a5462;
    border: none;
    border-radius: 4px;
    min-width: 8px;
    max-width: 8px;
    min-height: 8px;
    max-height: 8px;
}
QFrame#statusDot[active="true"] {
    background-color: #3ab7c9;
}

/* --------------------------------------------------------------- typography */
QLabel#pageTitle {
    font-size: 19px;
    font-weight: 600;
    color: #e9eef4;
}
QLabel#pageSubtitle {
    font-size: 13px;
    color: #98a4b3;
}
QLabel#sectionTitle {
    font-size: 13px;
    font-weight: 600;
    color: #c8d2dd;
    padding-top: 6px;
}
QLabel#hint {
    font-size: 12px;
    color: #6b7683;
}
QLabel#muted {
    font-size: 12px;
    color: #98a4b3;
}
QLabel#countLabel {
    font-size: 12px;
    font-weight: 600;
    color: #98a4b3;
}
QLabel#errorLabel {
    font-size: 12px;
    color: #f0554f;
}
QLabel#fieldCaption {
    font-size: 12px;
    color: #98a4b3;
}
QLabel#fieldValue {
    font-size: 13px;
    color: #e9eef4;
}
QLabel#fieldMono {
    font-size: 13px;
    font-family: "Consolas";
    color: #e9eef4;
}
QLabel#identityTitle {
    font-size: 17px;
    font-weight: 600;
    color: #e9eef4;
}
QLabel#scoreLabel {
    font-size: 17px;
    font-weight: 700;
}
QLabel#brandTitle {
    font-size: 14px;
    font-weight: 600;
    color: #e9eef4;
}
QLabel#brandMeta {
    font-size: 11px;
    color: #6b7683;
}
QLabel#monitorState {
    font-size: 11px;
    color: #6b7683;
}
QLabel#statusLabel {
    font-size: 12px;
    color: #98a4b3;
    padding-right: 12px;
}
QLabel#bodyText {
    font-size: 13px;
    color: #c8d2dd;
}
QLabel#detailBox {
    background-color: #141a22;
    border: 1px solid #232c38;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 13px;
    color: #c8d2dd;
}

/* ------------------------------------------------------------------- sidebar */
QPushButton#navButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    color: #98a4b3;
    font-size: 13px;
    padding: 9px 12px;
    text-align: left;
}
QPushButton#navButton:hover {
    background-color: #131b24;
    color: #dfe6ee;
}
QPushButton#navButton:focus {
    border: 1px solid #2f6472;
}
QPushButton#navButton:checked {
    background-color: #16222c;
    border: 1px solid #24404e;
    color: #e9eef4;
    font-weight: 600;
}

/* ------------------------------------------------------------------ buttons */
QPushButton {
    background-color: #1a222d;
    border: 1px solid #2b3542;
    border-radius: 5px;
    color: #dfe6ee;
    font-size: 13px;
    padding: 8px 14px;
}
QPushButton:hover {
    background-color: #202a36;
    border-color: #36424f;
}
QPushButton:pressed {
    background-color: #151c25;
}
QPushButton:disabled {
    background-color: #161d26;
    border-color: #222b36;
    color: #5c6673;
}
QPushButton#primaryButton {
    background-color: #3ab7c9;
    border: none;
    color: #07141a;
    font-size: 13px;
    font-weight: 600;
    padding: 9px 16px;
}
QPushButton#primaryButton:hover {
    background-color: #52c9da;
}
QPushButton#primaryButton:pressed {
    background-color: #2ea2b3;
}
QPushButton#primaryButton:disabled {
    background-color: #1a222d;
    color: #5c6673;
}
QPushButton#secondaryButton {
    background-color: #1a222d;
    border: 1px solid #2b3542;
    color: #dfe6ee;
    font-size: 13px;
    padding: 8px 14px;
}
QPushButton#secondaryButton:hover {
    background-color: #202a36;
    border-color: #36424f;
}
QPushButton#secondaryButton:pressed {
    background-color: #151c25;
}
QPushButton#secondaryButton:disabled {
    background-color: #161d26;
    border-color: #222b36;
    color: #5c6673;
}

/* ------------------------------------------------------------------- inputs */
QLineEdit, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit, QComboBox {
    background-color: #10161d;
    border: 1px solid #2b3542;
    border-radius: 5px;
    color: #e9eef4;
    font-size: 13px;
    padding: 6px 9px;
    selection-background-color: #3ab7c9;
    selection-color: #07141a;
}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QPlainTextEdit:focus,
QTextEdit:focus, QComboBox:focus {
    border: 1px solid #3ab7c9;
}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
    background-color: #141a22;
    color: #5c6673;
}
QLineEdit#searchField {
    padding-left: 10px;
}
QComboBox::drop-down {
    background: transparent;
    border: none;
    width: 22px;
}
QComboBox QAbstractItemView {
    background-color: #141a22;
    border: 1px solid #2b3542;
    color: #e9eef4;
    selection-background-color: #16222c;
    selection-color: #e9eef4;
}

/* ------------------------------------------------------------------ tables */
QTableView {
    background-color: #11171e;
    alternate-background-color: #141b24;
    border: 1px solid #232c38;
    border-radius: 6px;
    color: #dfe6ee;
    font-size: 13px;
    gridline-color: #1d2530;
    selection-background-color: #1b2f3b;
    selection-color: #e9eef4;
}
QTableView::item {
    border: none;
    padding: 4px 6px;
}
QTableView::item:selected {
    background-color: #1b2f3b;
    color: #e9eef4;
}
QHeaderView::section {
    background-color: #141a22;
    border: none;
    border-bottom: 1px solid #232c38;
    border-right: 1px solid #1d2530;
    color: #98a4b3;
    font-size: 12px;
    font-weight: 600;
    padding: 7px 8px;
}
QHeaderView::section:hover {
    background-color: #1a222d;
    color: #dfe6ee;
}
QTableCornerButton::section {
    background-color: #141a22;
    border: none;
}

/* --------------------------------------------------------------------- tabs */
QTabWidget::pane {
    background-color: #11171e;
    border: 1px solid #232c38;
    border-radius: 6px;
    top: -1px;
}
QTabBar::tab {
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: #98a4b3;
    font-size: 13px;
    margin-right: 2px;
    padding: 9px 14px;
}
QTabBar::tab:selected {
    border-bottom: 2px solid #3ab7c9;
    color: #e9eef4;
    font-weight: 600;
}
QTabBar::tab:hover {
    background-color: #151d26;
    color: #c8d2dd;
}

/* ------------------------------------------------------------------ panels */
QGroupBox {
    background-color: #141a22;
    border: 1px solid #232c38;
    border-radius: 6px;
    color: #e9eef4;
    font-size: 13px;
    font-weight: 600;
    margin-top: 18px;
    padding: 16px 14px 14px 14px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    background-color: #141a22;
    color: #98a4b3;
    left: 12px;
    padding: 0 6px;
    top: 2px;
}
QFrame#statStrip {
    background-color: #141a22;
    border: 1px solid #232c38;
    border-radius: 6px;
}
QLabel#statValue {
    font-size: 30px;
    font-weight: 600;
    color: #e9eef4;
}
QLabel#statCaption {
    font-size: 12px;
    color: #98a4b3;
}

/* ------------------------------------------------------------ chrome / misc */
QStatusBar {
    background-color: #0c1116;
    border-top: 1px solid #232c38;
    color: #98a4b3;
    font-size: 12px;
}
QToolTip {
    background-color: #1a222d;
    border: 1px solid #2b3542;
    color: #e9eef4;
    font-size: 12px;
    padding: 5px 8px;
}
QScrollBar:vertical {
    background: #0f141a;
    border: none;
    margin: 0;
    width: 11px;
}
QScrollBar::handle:vertical {
    background: #2b3542;
    border-radius: 5px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: #3a4756;
}
QScrollBar:horizontal {
    background: #0f141a;
    border: none;
    height: 11px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #2b3542;
    border-radius: 5px;
    min-width: 28px;
}
QScrollBar::handle:horizontal:hover {
    background: #3a4756;
}
QScrollBar::add-line, QScrollBar::sub-line {
    height: 0;
    width: 0;
    border: none;
}
QScrollBar::add-page, QScrollBar::sub-page {
    background: transparent;
}
QAbstractScrollArea::corner {
    background: transparent;
}
"""


def stylesheet() -> str:
    """Return the application stylesheet."""
    return STYLESHEET


def apply_theme(application: QApplication) -> None:
    """Apply the instrument-panel theme and matching palette to ``application``."""
    ui_family, mono_family = resolve_families()
    global _MONO_FAMILY  # noqa: PLW0603 - module-level font cache for table cells
    _MONO_FAMILY = mono_family

    application.setStyle("Fusion")
    application.setPalette(_dark_palette())
    application.setFont(QFont(ui_family, 10))
    application.setStyleSheet(STYLESHEET)


def _dark_palette() -> QPalette:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(GRAPHITE))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT_HI))
    palette.setColor(QPalette.ColorRole.Base, QColor("#11171e"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#141b24"))
    palette.setColor(QPalette.ColorRole.Text, QColor(TEXT_HI))
    palette.setColor(QPalette.ColorRole.Button, QColor(RAISED))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT_HI))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#07141a"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(RAISED))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT_HI))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(TEXT_LOW))
    palette.setColor(QPalette.ColorRole.Dark, QColor(LINE))
    return palette
