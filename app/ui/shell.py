"""Application shell placeholder.

Phase 7 replaces this with the full navigation shell (Dashboard, Live Networks,
Alerts, Trusted Networks, History, Settings, About). For now it only proves
that the window opens and exits cleanly.
"""

from __future__ import annotations

import logging

from app import APP_NAME, VERSION
from app.core.config import Config

logger = logging.getLogger(__name__)

__all__ = ["create_main_window", "run_app"]


def create_main_window():
    """Create the top-level window. Import PySide6 lazily."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel, QMainWindow, QVBoxLayout, QWidget

    window = QMainWindow()
    window.setWindowTitle(f"{APP_NAME} {VERSION}")
    window.resize(1000, 640)

    central = QWidget(window)
    layout = QVBoxLayout(central)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

    title = QLabel(f"{APP_NAME} {VERSION}", central)
    title.setAlignment(Qt.AlignmentFlag.AlignCenter)
    title.setStyleSheet("font-size: 24px; font-weight: bold;")

    subtitle = QLabel(
        "Foundation build — scanning, detection and dashboards arrive in later phases.",
        central,
    )
    subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
    subtitle.setWordWrap(True)

    layout.addWidget(title)
    layout.addWidget(subtitle)
    window.setCentralWidget(central)

    status = window.statusBar()
    status.showMessage("Ready — no monitoring active.")
    return window


def run_app(config: Config) -> int:
    """Start the Qt event loop and return a process exit code."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)

    window = create_main_window()
    window.show()
    logger.info("Graphical interface started (scan interval %ss)", config.scan_interval_seconds)
    return int(app.exec())
