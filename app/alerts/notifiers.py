"""Desktop notification adapters.

Everything here is free functionality already present on Windows: the primary
channel is a PowerShell toast (no third-party SDK, no cloud service). When a
notification cannot be delivered the adapter reports ``False`` and the caller
falls back to the in-app alert list, which is always authoritative.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from typing import Protocol, runtime_checkable

from app.models import Alert

logger = logging.getLogger(__name__)

__all__ = [
    "CompositeNotifier",
    "LogNotifier",
    "Notifier",
    "NullNotifier",
    "WindowsToastNotifier",
]

if hasattr(subprocess, "CREATE_NO_WINDOW"):
    _NO_WINDOW = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
else:  # pragma: no cover - non-Windows platforms
    _NO_WINDOW = 0

# AUMID of Windows PowerShell, used so un-packaged apps can raise toasts.
DEFAULT_APP_ID = (
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
    r"\WindowsPowerShell\v1.0\powershell.exe"
)

TOAST_SCRIPT = """
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$nodes = $template.GetElementsByTagName('text')
$nodes.Item(0).AppendChild($template.CreateTextNode($env:RAPH_TITLE)) | Out-Null
$nodes.Item(1).AppendChild($template.CreateTextNode($env:RAPH_MESSAGE)) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:RAPH_APP_ID).Show($toast)
"""


@runtime_checkable
class Notifier(Protocol):
    """Anything that can deliver an alert notification."""

    def notify(self, alert: Alert) -> bool:
        """Deliver a notification; return whether it succeeded."""
        ...


class NullNotifier:
    """Discards notifications (used when the user disables them)."""

    def notify(self, alert: Alert) -> bool:
        """Do nothing and report success so callers stop retrying."""
        del alert
        return True


class LogNotifier:
    """Writes notifications to the application log (always available)."""

    def notify(self, alert: Alert) -> bool:
        """Log the alert at warning level."""
        logger.warning(
            "ALERT [%s] %s score=%s :: %s",
            alert.severity.value if alert.severity else "unknown",
            alert.alert_type.value,
            alert.risk_score,
            alert.evidence,
        )
        return True


class WindowsToastNotifier:
    """Shows a Windows toast using the built-in PowerShell runtime.

    Failure to display a toast never raises: the method logs and returns
    ``False`` so callers can fall back to log/in-app notification.
    """

    def __init__(
        self,
        *,
        app_id: str = DEFAULT_APP_ID,
        timeout: float = 10.0,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._app_id = app_id
        self._timeout = timeout
        self._runner = runner
        self._env = dict(os.environ if env is None else env)

    @property
    def available(self) -> bool:
        """``True`` when PowerShell is present on this system."""
        return shutil.which("powershell") is not None or shutil.which("pwsh") is not None

    def notify(self, alert: Alert) -> bool:
        """Display a toast for ``alert``; ``False`` when it could not show."""
        if not self.available:
            logger.debug("toast skipped: PowerShell not found")
            return False

        environment = dict(self._env)
        environment["RAPH_TITLE"] = f"{alert.severity.value.upper() if alert.severity else 'ALERT'}: {alert.alert_type.value.replace('_', ' ').title()}"
        environment["RAPH_MESSAGE"] = f"{alert.ssid or '<hidden>'} [{alert.bssid or 'unknown BSSID'}] — {alert.evidence}"
        environment["RAPH_APP_ID"] = self._app_id

        command = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        arguments = [
            command,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            TOAST_SCRIPT,
        ]

        try:
            if self._runner is not None:
                completed = self._runner(arguments, self._timeout, environment)
                return bool(getattr(completed, "returncode", 1) == 0)
            completed = subprocess.run(  # noqa: S603 - fixed argument list, no shell
                arguments,
                env=environment,
                timeout=self._timeout,
                capture_output=True,
                check=False,
                creationflags=_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("toast notification failed: %s", exc)
            return False

        if completed.returncode != 0:
            stderr = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
            logger.debug("toast returned %s: %s", completed.returncode, stderr[:200])
            return False
        return True


class CompositeNotifier:
    """Tries each notifier in order and stops at the first success."""

    def __init__(self, *notifiers: Notifier) -> None:
        self._notifiers = [n for n in notifiers if n is not None]

    def notify(self, alert: Alert) -> bool:
        """Deliver via the first notifier that succeeds."""
        for notifier in self._notifiers:
            try:
                if notifier.notify(alert):
                    return True
            except Exception:  # pragma: no cover - defensive, never break monitoring
                logger.exception("notifier %s raised unexpectedly", type(notifier).__name__)
        return False
