"""Unit tests for security classification."""

from __future__ import annotations

import pytest

from app.models import SecurityMode, classify_security, is_enterprise_security


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Open", SecurityMode.OPEN),
        ("open system", SecurityMode.OPEN),
        ("None", SecurityMode.OPEN),
        ("WEP", SecurityMode.WEP),
        ("WPA", SecurityMode.WPA),
        ("TKIP", SecurityMode.UNKNOWN),
        ("WPA2-Personal", SecurityMode.WPA2),
        ("WPA2", SecurityMode.WPA2),
        ("RSN", SecurityMode.WPA2),
        ("WPA3-SAE", SecurityMode.WPA3),
        ("WPA3", SecurityMode.WPA3),
        ("garbage-value", SecurityMode.UNKNOWN),
    ],
)
def test_classify(raw: str, expected: SecurityMode) -> None:
    assert classify_security(raw) is expected


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_missing_reports_none(raw: object) -> None:
    assert classify_security(raw) is None


def test_strength_ordering() -> None:
    assert SecurityMode.OPEN.strength == 0
    assert SecurityMode.WEP.strength == 1
    assert SecurityMode.WPA2.strength == 3
    assert SecurityMode.WPA3.strength == 4
    assert SecurityMode.UNKNOWN.strength is None


def test_weaker_than_compares_only_known_modes() -> None:
    assert SecurityMode.OPEN.is_weaker_than(SecurityMode.WPA2)
    assert not SecurityMode.WPA2.is_weaker_than(SecurityMode.OPEN)
    assert not SecurityMode.UNKNOWN.is_weaker_than(SecurityMode.OPEN)
    assert not SecurityMode.WPA2.is_weaker_than(SecurityMode.UNKNOWN)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("WPA2-Enterprise", True), ("802.1X", True), ("WPA2-Personal", False), (None, False)],
)
def test_enterprise_detection(raw: str | None, expected: bool) -> None:
    assert is_enterprise_security(raw) is expected
