"""Unit tests for the interface parser."""

from __future__ import annotations

from app.parser import InterfaceInfo, parse_interfaces


def test_parses_connected_interface(load_fixture) -> None:
    interfaces = parse_interfaces(load_fixture("netsh_show_interfaces_connected.txt"))
    assert len(interfaces) == 1
    info = interfaces[0]
    assert info.name == "Wi-Fi"
    assert "Killer Wireless" in (info.description or "")
    assert info.mac_address == "9c:b6:d0:ec:ce:4d"
    assert info.state == "connected"
    assert info.ssid == "Unknown ip"
    assert info.bssid == "6a:0e:65:aa:3f:c9"
    assert info.channel == 149
    assert info.authentication == "WPA3-Personal"
    assert info.signal == 100
    assert info.rssi == -42
    assert info.is_connected
    assert info.is_up


def test_no_interfaces(load_fixture) -> None:
    assert parse_interfaces(load_fixture("netsh_show_interfaces_none.txt")) == []


def test_empty_text() -> None:
    assert parse_interfaces("") == []
    assert parse_interfaces("random noise") == []


def test_disconnected_state_is_not_connected() -> None:
    text = (
        "There is 1 interface on the system:\n\n"
        "    Name     : Wi-Fi\n"
        "    State    : disconnected\n"
    )
    (info,) = parse_interfaces(text)
    assert not info.is_connected
    assert info.is_up
    assert info.ssid is None


def test_malformed_values_do_not_raise() -> None:
    text = (
        "    Name     : Wi-Fi\n"
        "    State    : 12345\n"
        "    Channel  : abc\n"
        "    Signal   : loud\n"
        "    Physical address : not-a-mac\n"
        "    Rssi     : very strong\n"
    )
    (info,) = parse_interfaces(text)
    assert info.channel is None
    assert info.signal is None
    assert info.rssi is None
    assert info.mac_address is None
    assert info.raw  # raw capture still available for diagnostics


# --------------------------------------------------------------------- locale


def test_localized_output_starts_block_on_guid_and_recovers_by_shape(load_fixture) -> None:
    """Spanish labels: the block starts on the GUID and MAC/%/int recover."""
    (info,) = parse_interfaces(load_fixture("netsh_show_interfaces_localized_es.txt"))
    assert info.name is None  # the "Name" label did not translate to English
    assert info.mac_address == "00:11:22:33:44:55"
    assert info.ssid == "Oficina-5G"
    assert info.bssid == "38:af:29:aa:bb:01"
    assert info.channel == 44
    assert info.signal == 87
    assert info.state is None  # the "State" label did not translate
    assert info.is_connected  # a reported BSSID is locale-proof evidence


def test_second_unlabelled_mac_is_taken_as_bssid() -> None:
    text = (
        "    GUID     : {8a9d6f12-3c4e-4b5a-9c7d-1e2f3a4b5c6d}\n"
        "    Some address : 00:11:22:33:44:55\n"
        "    Other address : aa:bb:cc:dd:ee:ff\n"
    )
    (info,) = parse_interfaces(text)
    assert info.mac_address == "00:11:22:33:44:55"
    assert info.bssid == "aa:bb:cc:dd:ee:ff"
    assert info.is_connected


def test_bssid_presence_marks_connected_and_its_absence_does_not() -> None:
    assert InterfaceInfo(state="conectado", bssid="aa:bb:cc:dd:ee:ff").is_connected
    assert not InterfaceInfo(state="disconnected").is_connected
    assert not InterfaceInfo(state="desconectado").is_connected
