"""Alert lifecycle: creation, deduplication, acknowledgement, resolution and
notification on meaningful transitions only."""

from __future__ import annotations

from app.alerts.manager import AlertManager, AlertTransition
from app.alerts.notifiers import (
    CompositeNotifier,
    LogNotifier,
    Notifier,
    NullNotifier,
    WindowsToastNotifier,
)

__all__ = [
    "AlertManager",
    "AlertTransition",
    "CompositeNotifier",
    "LogNotifier",
    "Notifier",
    "NullNotifier",
    "WindowsToastNotifier",
]
