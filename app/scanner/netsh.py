"""Windows ``netsh wlan`` scanner adapter.

Read-only by construction: the adapter only ever invokes the two display
commands ``netsh wlan show networks mode=bssid`` and
``netsh wlan show interfaces``. It never passes ``shell=True``, never changes
network configuration and never connects to a network.

The adapter returns raw text; interpretation belongs to :mod:`app.parser`.
"""

from __future__ import annotations

import locale
import logging
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.scanner.errors import ScannerError, ScannerTimeoutError, ScannerUnavailableError
from app.scanner.raw import RawScanResult

logger = logging.getLogger(__name__)

__all__ = ["NetshScanner", "ScanCommand"]

DEFAULT_TIMEOUT_SECONDS = 20.0
INTERFACE_COUNT_PATTERN = re.compile(r"there (?:is|are)\s+(\d+)\s+interfaces?\s+on the system", re.IGNORECASE)

if hasattr(subprocess, "CREATE_NO_WINDOW"):
    _NO_WINDOW = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
else:  # pragma: no cover - non-Windows platforms
    _NO_WINDOW = 0


@dataclass(frozen=True, slots=True)
class ScanCommand:
    """A single read-only command the adapter is allowed to run."""

    name: str
    args: tuple[str, ...]
    purpose: str


NETWORKS_COMMAND = ScanCommand(
    name="networks",
    args=("netsh", "wlan", "show", "networks", "mode=bssid"),
    purpose="list visible wireless networks with per-BSSID detail",
)
INTERFACES_COMMAND = ScanCommand(
    name="interfaces",
    args=("netsh", "wlan", "show", "interfaces"),
    purpose="list wireless interfaces and connection state",
)

# Injectable for tests: signature matches subprocess.run without kwargs noise.
CommandRunner = Callable[..., "subprocess.CompletedProcess[bytes]"]


def _decode(raw: bytes) -> str:
    """Decode command output, tolerating legacy Windows codepages.

    UTF-8 is tried first (it is what modern consoles emit); if the bytes are
    not valid UTF-8 the Windows ANSI codepage is used with replacement
    characters instead of raising, so a single odd byte never kills a scan.
    """
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        ansi = locale.getpreferredencoding(False) or "cp1252"
        try:
            return raw.decode(ansi)
        except (UnicodeDecodeError, LookupError):
            return raw.decode("utf-8", errors="replace")


def _default_runner(args: tuple[str, ...], timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        list(args),
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=_NO_WINDOW,
    )


class NetshScanner:
    """Read-only Windows WLAN scanner.

    Parameters
    ----------
    timeout:
        Seconds before the command is aborted.
    runner:
        Injectable command runner for tests; must accept ``(args, timeout)``.
    executable:
        Overrides how the ``netsh`` executable is located.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        runner: CommandRunner | None = None,
        executable: str | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        self._timeout = timeout
        self._runner = runner or _default_runner
        self._executable = executable

    # ------------------------------------------------------------- internals

    def _resolve_executable(self) -> str:
        if self._executable:
            return self._executable
        found = shutil.which("netsh")
        if not found:
            raise ScannerUnavailableError(
                "the 'netsh' command was not found on this system; "
                "Wi-Fi scanning requires Windows with WLAN support"
            )
        return found

    def _execute(self, command: ScanCommand) -> RawScanResult:
        executable = self._resolve_executable()
        args = (executable, *command.args[1:])
        started = time.perf_counter()
        try:
            completed = self._runner(args, self._timeout)
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - started
            logger.warning("%s timed out after %.1fs", command.name, duration)
            raise ScannerTimeoutError(
                f"{command.name} scan exceeded the {self._timeout:.0f}s timeout"
            ) from exc
        except OSError as exc:
            raise ScannerUnavailableError(f"could not execute {args[0]}: {exc}") from exc
        duration = time.perf_counter() - started

        stdout = _decode(completed.stdout or b"")
        stderr = _decode(completed.stderr or b"")
        result = RawScanResult.create(
            command=args,
            stdout=stdout,
            stderr=stderr,
            returncode=completed.returncode,
            duration_seconds=duration,
        )
        logger.debug("%s", result.summary())
        return result

    # ------------------------------------------------------------- public API

    def scan(self) -> RawScanResult:
        """Run a visibility scan and return the raw output.

        Raises :class:`ScannerUnavailableError` when the WLAN facility is
        missing and :class:`ScannerTimeoutError` when the command hangs.
        A command that runs but exits non-zero is returned as-is so callers
        can inspect it.
        """
        result = self._execute(NETWORKS_COMMAND)
        if not result.ok:
            logger.warning("scan command reported an error: %s", result.summary())
        return result

    def show_interfaces(self) -> RawScanResult:
        """Return raw interface/status output (read-only)."""
        return self._execute(INTERFACES_COMMAND)

    def available(self) -> tuple[bool, str]:
        """Report whether WLAN scanning is usable.

        Returns ``(usable, detail)``. The detail string is safe to show to an
        operator and never contains sensitive data.
        """
        try:
            result = self.show_interfaces()
        except ScannerError as exc:
            return False, str(exc)

        if not result.ok:
            detail = (result.stderr or result.stdout).strip().splitlines()
            return False, detail[0] if detail else f"command failed with code {result.returncode}"

        match = INTERFACE_COUNT_PATTERN.search(result.stdout)
        if match and int(match.group(1)) == 0:
            return False, "no wireless interfaces are present on this system"

        return True, "wireless interface available"
