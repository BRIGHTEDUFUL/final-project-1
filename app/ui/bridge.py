"""Qt bridge: worker-thread events marshalled to the GUI thread.

Monitoring callbacks run on a background thread. Emitting Qt signals from that
thread is safe: Qt queues cross-thread signal deliveries until the receiver
lives in the GUI thread, so slots always execute on the UI thread.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from app.services import ScanReport

__all__ = ["MonitorBridge"]


class MonitorBridge(QObject):
    """Relays monitoring events from the worker thread to UI slots."""

    report_ready = Signal(object)  # ScanReport
    error_raised = Signal(str)  # human-readable failure detail
    monitoring_changed = Signal(bool)  # True when monitoring started
    alert_count_changed = Signal(int)  # open alert total after a scan

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)

    def emit_report(self, report: ScanReport) -> None:
        """Called from the monitoring thread; safe to invoke directly."""
        self.report_ready.emit(report)
        if report.ok:
            self.alert_count_changed.emit(sum(1 for t in report.alerts if t.created))

    def emit_error(self, message: str) -> None:
        """Called from the monitoring thread when a scan fails."""
        self.error_raised.emit(message)
