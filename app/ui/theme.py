"""Visual theme: one dark, professional stylesheet shared by every screen."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

__all__ = ["ACCENT", "CRITICAL_COLOR", "HIGH_COLOR", "LOW_COLOR", "SUSPICIOUS_COLOR", "apply_theme", "stylesheet"]

ACCENT = "#4f8cff"
LOW_COLOR = "#3fae6b"
SUSPICIOUS_COLOR = "#e0a63a"
HIGH_COLOR = "#e07a3f"
CRITICAL_COLOR = "#e04f4f"

SEVERITY_COLORS = {
    "low": LOW_COLOR,
    "suspicious": SUSPICIOUS_COLOR,
    "high": HIGH_COLOR,
    "critical": CRITICAL_COLOR,
}

STYLESHEET = """
QWidget {
    background-color: #14181f;
    color: #d7dde5;
    font-size: 13px;
}
QMainWindow, QDialog {
    background-color: #14181f;
}
QLabel#pageTitle {
    font-size: 20px;
    font-weight: 600;
    color: #f2f5f9;
}
QLabel#statValue {
    font-size: 26px;
    font-weight: 700;
    color: #f2f5f9;
}
QLabel#statCaption {
    font-size: 12px;
    color: #8b95a3;
}
QFrame#sidebar {
    background-color: #10141a;
    border-right: 1px solid #232a34;
}
QPushButton#navButton {
    text-align: left;
    padding: 10px 14px;
    border: none;
    border-radius: 6px;
    background-color: transparent;
    color: #aab3c0;
    font-size: 13px;
}
QPushButton#navButton:hover {
    background-color: #1b2735;
    color: #e6ebf2;
}
QPushButton#navButton:checked {
    background-color: #1f3350;
    color: #ffffff;
    font-weight: 600;
}
QPushButton#primaryButton {
    background-color: __ACCENT__;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}
QPushButton#primaryButton:hover {
    background-color: #6ba0ff;
}
QPushButton#primaryButton:disabled {
    background-color: #2a3140;
    color: #6b7482;
}
QPushButton#secondaryButton {
    background-color: #1b2735;
    border: 1px solid #2b3543;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton#secondaryButton:hover {
    background-color: #23303f;
}
QLineEdit, QSpinBox, QPlainTextEdit, QComboBox {
    background-color: #10151c;
    border: 1px solid #2a323e;
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: __ACCENT__;
}
QLineEdit:focus, QSpinBox:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid __ACCENT__;
}
QTableWidget, QTableView {
    background-color: #0f131a;
    alternate-background-color: #131923;
    gridline-color: #1e2530;
    border: 1px solid #232a34;
    border-radius: 6px;
}
QHeaderView::section {
    background-color: #171d26;
    color: #97a1b0;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #232a34;
    border-bottom: 1px solid #232a34;
}
QTableView::item:selected {
    background-color: #1f3350;
    color: #ffffff;
}
QScrollBar:vertical {
    background: #10141a;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #2a323e;
    border-radius: 5px;
    min-height: 24px;
}
QStatusBar {
    background-color: #10141a;
    color: #8b95a3;
    border-top: 1px solid #232a34;
}
QGroupBox {
    border: 1px solid #232a34;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
    font-weight: 600;
    color: #c7cfda;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QTabWidget::pane {
    border: 1px solid #232a34;
    border-radius: 6px;
}
QTabBar::tab {
    background: #10151c;
    color: #97a1b0;
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected {
    background: #1b2735;
    color: #ffffff;
}
QToolTip {
    background-color: #1b2735;
    color: #e6ebf2;
    border: 1px solid #2b3543;
    padding: 4px;
}
""".replace("__ACCENT__", ACCENT)


def stylesheet() -> str:
    """Return the application stylesheet."""
    return STYLESHEET


def apply_theme(application: QApplication) -> None:
    """Apply the dark theme and matching palette to ``application``."""
    application.setStyle("Fusion")
    application.setPalette(_dark_palette())
    application.setFont(QFont("Segoe UI", 10))
    application.setStyleSheet(STYLESHEET)


def _dark_palette() -> QPalette:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#14181f"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#d7dde5"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#0f131a"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#131923"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#d7dde5"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#1b2735"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#d7dde5"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#1b2735"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#e6ebf2"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#6b7482"))
    return palette
