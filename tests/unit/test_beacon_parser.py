"""Unit tests for the pure 802.11 beacon/probe-response frame parser.

All frames are synthesised from bytes: no capture driver, no network and no
live radio are required.
"""

from __future__ import annotations

import pytest

from app.capture import parse_frame
from tests.support import MICROSOFT_OUI, WFA_OUI, build_beacon, rsn_ie, vendor_ie

BSSID = "aa:bb:cc:dd:ee:ff"

# capability: ESS + privacy (bit 0 and bit 4)
CAPABILITY_ESS_PRIVACY = 0x0011
CAPABILITY_ESS = 0x0001


# ------------------------------------------------------------------ happy path


def test_bare_beacon_parses_fully() -> None:
    raw = build_beacon(
        bssid=BSSID,
        capability=CAPABILITY_ESS_PRIVACY,
        ies=(rsn_ie(caps=0x00C0),),
    )

    info = parse_frame(raw)

    assert info is not None
    assert info.bssid == BSSID
    assert info.frame_kind == "beacon"
    assert info.ssid == "LabNet"
    assert info.hidden is False
    assert info.channel == 6
    assert info.beacon_interval == 100
    assert info.privacy is True
    assert info.rsn is not None
    assert info.rsn.uses_psk is True
    assert info.rsn.uses_sae is False
    assert info.rsn.mfpc is True
    assert info.rsn.mfpr is True
    assert info.wpa1 is False
    assert info.wps is False
    assert info.wep_era is False


def test_radiotap_wrapped_beacon_parses_identically() -> None:
    raw = build_beacon(bssid=BSSID, radiotap=True, ies=(rsn_ie(),))

    info = parse_frame(raw)

    assert info is not None
    assert info.bssid == BSSID
    assert info.frame_kind == "beacon"
    assert info.ssid == "LabNet"
    assert info.channel == 6


def test_probe_response_parses_as_probe_response() -> None:
    info = parse_frame(build_beacon(subtype=5, bssid=BSSID))

    assert info is not None
    assert info.frame_kind == "probe_response"
    assert info.bssid == BSSID


def test_order_bit_ht_control_is_accounted_for() -> None:
    info = parse_frame(build_beacon(bssid=BSSID, order=True))

    assert info is not None
    assert info.bssid == BSSID
    assert info.ssid == "LabNet"


def test_missing_ds_parameter_leaves_channel_unknown() -> None:
    info = parse_frame(build_beacon(channel=None))

    assert info is not None
    assert info.channel is None


def test_non_utf8_ssid_decodes_without_raising() -> None:
    info = parse_frame(build_beacon(ssid=b"\xff\xfe-lab"))

    assert info is not None
    assert isinstance(info.ssid, str)
    assert info.hidden is False


# ------------------------------------------------------------------ SSID states


def test_empty_ssid_is_hidden() -> None:
    info = parse_frame(build_beacon(ssid=b""))

    assert info is not None
    assert info.hidden is True
    assert info.ssid is None


def test_absent_ssid_element_is_hidden() -> None:
    info = parse_frame(build_beacon(ssid=None))

    assert info is not None
    assert info.hidden is True
    assert info.ssid is None


# ------------------------------------------------------------------- security


def test_sae_akm_reports_wpa3() -> None:
    info = parse_frame(build_beacon(ies=(rsn_ie(akm=(8,)),)))

    assert info is not None
    assert info.rsn is not None
    assert info.rsn.uses_sae is True
    assert info.rsn.uses_psk is False


def test_ft_sae_akm_reports_wpa3() -> None:
    info = parse_frame(build_beacon(ies=(rsn_ie(akm=(9,)),)))

    assert info is not None
    assert info.rsn is not None
    assert info.rsn.uses_sae is True


def test_wps_and_wpa1_vendor_elements_detected() -> None:
    info = parse_frame(
        build_beacon(
            ies=(vendor_ie(MICROSOFT_OUI, 4), vendor_ie(MICROSOFT_OUI, 1)),
        )
    )

    assert info is not None
    assert info.wps is True
    assert info.wpa1 is True


def test_wfa_wps_vendor_element_detected() -> None:
    info = parse_frame(build_beacon(ies=(vendor_ie(WFA_OUI, 4),)))

    assert info is not None
    assert info.wps is True
    assert info.wpa1 is False


def test_privacy_without_any_wpa_element_is_wep_era() -> None:
    info = parse_frame(build_beacon(capability=CAPABILITY_ESS_PRIVACY))

    assert info is not None
    assert info.privacy is True
    assert info.rsn is None
    assert info.wpa1 is False
    assert info.wep_era is True


def test_wpa1_element_suppresses_wep_era_classification() -> None:
    info = parse_frame(
        build_beacon(capability=CAPABILITY_ESS_PRIVACY, ies=(vendor_ie(MICROSOFT_OUI, 1),))
    )

    assert info is not None
    assert info.wep_era is False


@pytest.mark.parametrize(
    ("caps", "mfpc", "mfpr"),
    [(0x0000, False, False), (0x0040, True, False), (0x00C0, True, True)],
)
def test_rsn_management_frame_protection_flags(caps: int, mfpc: bool, mfpr: bool) -> None:
    info = parse_frame(build_beacon(ies=(rsn_ie(caps=caps),)))

    assert info is not None
    assert info.rsn is not None
    assert info.rsn.mfpc is mfpc
    assert info.rsn.mfpr is mfpr


# ---------------------------------------------------------- rejected frame kinds


def test_data_frame_is_ignored() -> None:
    assert parse_frame(build_beacon(frame_type=2, subtype=0)) is None


def test_other_management_subtype_is_ignored() -> None:
    # association request (type 0, subtype 0)
    assert parse_frame(build_beacon(subtype=0)) is None


@pytest.mark.parametrize("raw", [b"", b"\x80\x00", b"\x00\x00\x08\x00"])
def test_empty_or_tiny_input_is_none(raw: bytes) -> None:
    assert parse_frame(raw) is None


def test_non_bytes_input_is_none() -> None:
    assert parse_frame("beacon text") is None  # type: ignore[arg-type]


def test_truncated_trailing_element_keeps_earlier_evidence() -> None:
    full = build_beacon(ies=(rsn_ie(), vendor_ie(MICROSOFT_OUI, 4)))

    info = parse_frame(full[:-4])

    assert info is not None
    assert info.rsn is not None, "elements before the truncation must survive"
    assert info.bssid == BSSID


def test_truncated_fixed_parameters_are_rejected() -> None:
    raw = build_beacon()
    assert len(raw) > 36, "fixture must be large enough to truncate meaningfully"

    assert parse_frame(raw[: len(raw) // 2]) is None
    assert parse_frame(raw[:30]) is None


def test_garbage_bytes_do_not_raise() -> None:
    for raw in (b"\x80" + b"\xff" * 50, b"\x00\x00\x08\x00" + b"\xaa" * 40, bytes(range(200))):
        result = parse_frame(raw)
        assert result is None or (result.bssid and isinstance(result.frame_kind, str))
