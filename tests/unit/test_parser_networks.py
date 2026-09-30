"""Unit tests for the network scan parser."""

from __future__ import annotations

from datetime import UTC, datetime

from app.parser import (
    locale_diagnostic,
    parse_visible_networks,
    parse_visible_networks_as_observations,
)


def test_parses_real_single_network_output(load_fixture) -> None:
    observations = parse_visible_networks_as_observations(load_fixture("netsh_show_networks_single.txt"))
    assert len(observations) == 1
    observation = observations[0]
    assert observation.ssid == "Unknown ip"
    assert observation.bssid == "6a:0e:65:aa:3f:c9"
    assert observation.signal_strength == 100
    assert observation.channel == 149
    assert observation.security == "WPA3-Personal"


def test_parses_multiple_networks_and_radios(load_fixture) -> None:
    observations = parse_visible_networks_as_observations(load_fixture("netsh_show_networks_multi.txt"))
    assert len(observations) == 4

    corporate = [o for o in observations if o.ssid == "Corporate"]
    assert len(corporate) == 2
    assert {o.bssid for o in corporate} == {"10:20:30:40:50:60", "10:20:30:40:50:61"}
    assert all(o.security == "WPA2-Enterprise" for o in corporate)

    hidden = [o for o in observations if o.ssid is None]
    assert len(hidden) == 1
    assert hidden[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert hidden[0].signal_strength == 37
    assert hidden[0].channel == 6


def test_out_of_range_values_are_clamped_or_dropped(load_fixture) -> None:
    observations = parse_visible_networks_as_observations(load_fixture("netsh_show_networks_multi.txt"))
    guest = next(o for o in observations if o.ssid == "Guest")
    assert guest.signal_strength == 100  # 200% clamped
    assert guest.channel is None  # 999 is not a valid channel
    assert guest.security == "Open"


def test_open_with_wep_encryption_is_reported_as_wep(load_fixture) -> None:
    observations = parse_visible_networks_as_observations(load_fixture("netsh_show_networks_malformed.txt"))
    home_lab = next(o for o in observations if o.ssid == "HomeLab")
    assert home_lab.security == "WEP"


def test_empty_scan_returns_nothing(load_fixture) -> None:
    assert parse_visible_networks(load_fixture("netsh_show_networks_empty.txt")) == []
    assert parse_visible_networks_as_observations("") == []
    assert parse_visible_networks_as_observations("   \n  ") == []


def test_malformed_output_never_raises(load_fixture) -> None:
    observations = parse_visible_networks_as_observations(load_fixture("netsh_show_networks_malformed.txt"))
    # Networks parsed before the garbage still survive.
    assert any(o.ssid == "HomeLab" for o in observations)

    broken = [o for o in observations if o.ssid == "Broken"]
    # The malformed BSSID line degrades to a nameless radio instead of failing.
    assert {o.bssid for o in broken} == {None, "de:ad:be:ef:00:02"}

    home_lab = next(o for o in observations if o.ssid == "HomeLab")
    # Unknown labels and unparseable values must not erase valid data.
    assert home_lab.signal_strength == 71
    assert home_lab.channel == 11


def test_observed_at_is_applied_to_every_observation() -> None:
    stamp = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)
    text = "SSID 1 : Net\n    Authentication : WPA2-Personal\n    BSSID 1 : aa:bb:cc:dd:ee:ff\n"
    observations = parse_visible_networks_as_observations(text, observed_at=stamp)
    assert observations
    assert all(o.observed_at == stamp for o in observations)


def test_security_label_prefers_authentication() -> None:
    text = (
        "SSID 1 : Office\n"
        "    Authentication          : WPA3-SAE\n"
        "    Encryption              : GCMP-256\n"
        "    BSSID 1                 : aa:bb:cc:dd:ee:ff\n"
        "         Signal             : 90%\n"
    )
    (observation,) = parse_visible_networks_as_observations(text)
    assert observation.security == "WPA3-SAE"
    assert observation.signal_strength == 90


def test_ssid_without_bssid_still_yields_observation() -> None:
    text = "SSID 1 : Lonely\n    Authentication : WPA2-Personal\n"
    (observation,) = parse_visible_networks_as_observations(text)
    assert observation.ssid == "Lonely"
    assert observation.bssid is None
    assert observation.signal_strength is None


def test_values_with_colons_are_handled() -> None:
    text = (
        "SSID 1 : IPv6:lab\n"
        "    BSSID 1 : aa:bb:cc:dd:ee:ff\n"
        "         Signal : 55%\n"
    )
    (observation,) = parse_visible_networks_as_observations(text)
    assert observation.ssid == "IPv6:lab"
    assert observation.bssid == "aa:bb:cc:dd:ee:ff"


def test_intermediate_records_expose_security_label() -> None:
    text = "SSID 1 : X\n    Authentication : Open\n    Encryption : WEP\n"
    (record,) = parse_visible_networks(text)
    assert record.security_label() == "WEP"


# --------------------------------------------------------------------- locale


def test_localized_labels_recover_signal_and_channel_by_shape(load_fixture) -> None:
    """Spanish labels: percent/integer shapes still yield signal and channel."""
    observations = parse_visible_networks_as_observations(
        load_fixture("netsh_show_networks_localized_es.txt")
    )
    assert len(observations) == 2
    first, second = observations
    assert first.ssid == "Oficina-5G"
    assert first.bssid == "38:af:29:aa:bb:01"
    assert first.signal_strength == 87
    assert first.channel == 44
    assert second.bssid == "38:af:29:aa:bb:02"
    assert second.signal_strength == 54
    assert second.channel == 149
    # Security labels have no value shape — absence stays honest, not guessed.
    assert first.security is None
    assert second.security is None


def test_locale_diagnostic_flags_localized_output(load_fixture) -> None:
    note = locale_diagnostic(load_fixture("netsh_show_networks_localized_es.txt"))
    assert note is not None
    assert "non-English" in note
    assert "troubleshooting" in note


def test_locale_diagnostic_stays_silent_on_english(load_fixture) -> None:
    for name in (
        "netsh_show_networks_multi.txt",
        "netsh_show_networks_single.txt",
        "netsh_show_networks_malformed.txt",
        "netsh_show_networks_empty.txt",
    ):
        assert locale_diagnostic(load_fixture(name)) is None, name


def test_locale_diagnostic_ignores_empty_and_banner_only_text() -> None:
    assert locale_diagnostic("") is None
    assert locale_diagnostic("   \n") is None
    assert locale_diagnostic("There are 0 networks currently visible.\n") is None
