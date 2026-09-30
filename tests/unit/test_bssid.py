"""Unit tests for BSSID normalisation."""

from __future__ import annotations

import pytest

from app.models import (
    InvalidBssidError,
    ModelValidationError,
    normalize_bssid,
    normalize_bssid_list,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("AABB.CCDD.EEFF", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff"),
        ("AA BB CC DD EE FF", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb:cc:dd:ee:0f", "aa:bb:cc:dd:ee:0f"),
    ],
)
def test_normalise_variants(raw: str, expected: str) -> None:
    assert normalize_bssid(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_missing_values_return_none(raw: object) -> None:
    assert normalize_bssid(raw) is None


def test_all_zero_placeholder_returns_none() -> None:
    assert normalize_bssid("00:00:00:00:00:00") is None


@pytest.mark.parametrize(
    "raw",
    ["gg:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:11", "not-a-mac", "12345"],
)
def test_invalid_values_raise(raw: str) -> None:
    with pytest.raises(InvalidBssidError):
        normalize_bssid(raw)


def test_non_string_raises() -> None:
    with pytest.raises(InvalidBssidError):
        normalize_bssid(12345)


def test_list_normalises_deduplicates_and_keeps_order() -> None:
    result = normalize_bssid_list(["AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", None, "11:22:33:44:55:66"])
    assert result == ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")


def test_list_rejects_single_string() -> None:
    with pytest.raises(ModelValidationError):
        normalize_bssid_list("aa:bb:cc:dd:ee:ff")


def test_list_accepts_none() -> None:
    assert normalize_bssid_list(None) == ()
