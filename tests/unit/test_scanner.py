"""Unit tests for the Windows scanner adapter (mocked, no Wi-Fi required)."""

from __future__ import annotations

import subprocess

import pytest

from app.scanner import (
    NetshScanner,
    ScannerError,
    ScannerTimeoutError,
    ScannerUnavailableError,
)


class FakeRunner:
    """Records invocations and returns canned output."""

    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        error: BaseException | None = None,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.error = error
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(self, args: tuple[str, ...], timeout: float) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, timeout))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(list(args), self.returncode, self.stdout, self.stderr)


def test_scan_invokes_read_only_network_command(load_fixture) -> None:
    runner = FakeRunner(stdout=load_fixture("netsh_show_networks_single.txt").encode("utf-8"))
    scanner = NetshScanner(runner=runner, executable="netsh")

    result = scanner.scan()

    assert result.ok
    assert result.command == ("netsh", "wlan", "show", "networks", "mode=bssid")
    assert "Unknown ip" in result.stdout
    assert runner.calls[0][1] > 0  # a timeout was supplied
    # Read-only guarantee: the command never contains a mutating verb.
    forbidden = {"connect", "add", "delete", "set", "deleteprofile", "addprofile"}
    assert forbidden.isdisjoint({part.lower() for part in result.command})


def test_non_zero_exit_is_returned_for_inspection() -> None:
    runner = FakeRunner(stderr=b"The Wireless AutoConfig Service (wlansvc) is not running.\r\n", returncode=1)
    scanner = NetshScanner(runner=runner, executable="netsh")

    result = scanner.scan()

    assert not result.ok
    assert result.returncode == 1
    assert "wlansvc" in result.stderr
    assert "failed" in result.summary()


def test_timeout_raises_scanner_timeout_error() -> None:
    runner = FakeRunner(error=subprocess.TimeoutExpired(cmd="netsh", timeout=5))
    scanner = NetshScanner(runner=runner, executable="netsh")

    with pytest.raises(ScannerTimeoutError):
        scanner.scan()


def test_os_error_raises_scanner_unavailable() -> None:
    runner = FakeRunner(error=FileNotFoundError("netsh not found"))
    scanner = NetshScanner(runner=runner, executable="netsh")

    with pytest.raises(ScannerUnavailableError):
        scanner.show_interfaces()


def test_missing_executable_raises_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.scanner.netsh.shutil.which", lambda _name: None)
    scanner = NetshScanner(runner=FakeRunner())

    with pytest.raises(ScannerUnavailableError):
        scanner.scan()


def test_invalid_timeout_is_rejected() -> None:
    with pytest.raises(ValueError):
        NetshScanner(timeout=0)
    with pytest.raises(ValueError):
        NetshScanner(timeout=-1)


def test_available_when_interface_present(load_fixture) -> None:
    runner = FakeRunner(stdout=load_fixture("netsh_show_interfaces_connected.txt").encode("utf-8"))
    scanner = NetshScanner(runner=runner, executable="netsh")
    ok, detail = scanner.available()
    assert ok
    assert "available" in detail


def test_unavailable_when_no_interfaces(load_fixture) -> None:
    runner = FakeRunner(stdout=load_fixture("netsh_show_interfaces_none.txt").encode("utf-8"))
    scanner = NetshScanner(runner=runner, executable="netsh")
    ok, detail = scanner.available()
    assert not ok
    assert "no wireless interfaces" in detail


def test_unavailable_when_command_fails(load_fixture) -> None:
    runner = FakeRunner(
        stdout=load_fixture("netsh_service_not_running.txt").encode("utf-8"),
        returncode=1,
    )
    scanner = NetshScanner(runner=runner, executable="netsh")
    ok, detail = scanner.available()
    assert not ok
    assert "wlansvc" in detail


def test_unavailable_when_scanner_raises() -> None:
    scanner = NetshScanner(runner=FakeRunner(error=FileNotFoundError()), executable="netsh")
    ok, detail = scanner.available()
    assert not ok
    assert detail


@pytest.mark.parametrize("label", ["éé café", "日本語", "Ünïcödé"])
def test_non_ascii_output_decodes(label: str) -> None:
    text = f"SSID 1 : {label}\n"
    runner = FakeRunner(stdout=text.encode("utf-8"))
    scanner = NetshScanner(runner=runner, executable="netsh")
    assert label in scanner.scan().stdout


def test_legacy_codepage_output_falls_back_without_crashing() -> None:
    # cp1252 bytes that are invalid UTF-8: decoding must not raise.
    runner = FakeRunner(stdout="SSID 1 : café\r\n".encode("cp1252"))
    scanner = NetshScanner(runner=runner, executable="netsh")
    output = scanner.scan().stdout
    assert "caf" in output


def test_empty_output_is_handled() -> None:
    scanner = NetshScanner(runner=FakeRunner(stdout=b""), executable="netsh")
    result = scanner.scan()
    assert result.ok
    assert result.stdout == ""


def test_scanner_errors_share_base_class() -> None:
    assert issubclass(ScannerTimeoutError, ScannerError)
    assert issubclass(ScannerUnavailableError, ScannerError)


def test_raw_result_command_is_immutable_tuple() -> None:
    scanner = NetshScanner(runner=FakeRunner(), executable="netsh")
    result = scanner.scan()
    with pytest.raises((AttributeError, TypeError)):
        result.command.append("mode")  # type: ignore[attr-defined]
