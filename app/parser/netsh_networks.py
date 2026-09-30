"""Parser for ``netsh wlan show networks mode=bssid`` output.

The parser is deliberately defensive: unrecognised lines are ignored, missing
fields stay ``None`` and malformed values never raise. Output shape varies
with adapter, band and Windows version, so structure (indentation and key
position) drives the parse rather than a fixed line layout.

Locale note: Windows localises some labels. Values that are recognised by
shape (MAC addresses, percentages, integers) are extracted regardless of the
label language; English key aliases cover the semantic fields, and inside a
radio block a percent value or bare channel integer is recovered even when
its label translated. Unknown labels are never guessed — when the
frequently translated labels all go unrecognised, :func:`locale_diagnostic`
says so honestly instead of letting partial results pass silently.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime

from app.models import NetworkObservation, utcnow

logger = logging.getLogger(__name__)

__all__ = [
    "ParsedNetwork",
    "locale_diagnostic",
    "parse_visible_networks",
    "parse_visible_networks_as_observations",
]

_KEY_VALUE_PATTERN = re.compile(r"^(?P<indent>\s*)(?P<key>[^:]+?)\s*:\s*(?P<value>.*)$")
_BSSID_KEY_PATTERN = re.compile(r"^bssid\b", re.IGNORECASE)
_SSID_KEY_PATTERN = re.compile(r"^ssid(?:\s*\d+)?$", re.IGNORECASE)
_SIGNAL_PATTERN = re.compile(r"^(\d{1,3})\s*%$")
_CHANNEL_PATTERN = re.compile(r"^\s*(\d{1,4})\s*$")
_AUTH_KEY_PATTERN = re.compile(r"^(?:authentication|auth(?:entication)? mode)$", re.IGNORECASE)
_ENCRYPTION_KEY_PATTERN = re.compile(r"^(?:encryption|cipher)$", re.IGNORECASE)
_SIGNAL_KEY_PATTERN = re.compile(r"^(?:signal|signal quality)$", re.IGNORECASE)
_CHANNEL_KEY_PATTERN = re.compile(r"^channel$", re.IGNORECASE)

_OPEN_LABELS = {"open", "open system", "none", "not configured", "ov open system"}
_WEP_ENCRYPTION_LABELS = {"wep", "none + wep"}


@dataclass(slots=True)
class ParsedNetwork:
    """Intermediate parse result: one SSID with its radio entries."""

    ssid: str | None = None
    authentication: str | None = None
    encryption: str | None = None
    bssids: list[dict[str, object]] = field(default_factory=list)
    orphan_bssids: list[dict[str, object]] = field(default_factory=list)

    def security_label(self) -> str | None:
        """Compose the security label reported for this network."""
        auth = self.authentication.strip() if self.authentication else None
        cipher = self.encryption.strip() if self.encryption else None

        if auth and cipher and cipher.lower() in _WEP_ENCRYPTION_LABELS:
            if auth.lower() in _OPEN_LABELS:
                return "WEP"
        if auth:
            return auth
        if cipher and cipher.lower() not in {"none", "ccmp", "tkip", "gcmp-256"}:
            return cipher
        return None


def _clean(value: str) -> str | None:
    text = value.strip()
    return text or None


def _to_signal(value: str) -> int | None:
    match = _SIGNAL_PATTERN.match(value.strip())
    if not match:
        return None
    percent = int(match.group(1))
    return max(0, min(100, percent))


def _to_channel(value: str) -> int | None:
    match = _CHANNEL_PATTERN.match(value)
    if not match:
        return None
    channel = int(match.group(1))
    if 1 <= channel <= 255:
        return channel
    return None


def parse_visible_networks(text: str) -> list[ParsedNetwork]:
    """Parse raw scan text into intermediate network records."""
    if not text or not text.strip():
        return []

    networks: list[ParsedNetwork] = []
    current: ParsedNetwork | None = None
    current_radio: dict[str, object] | None = None

    def close_radio() -> None:
        nonlocal current_radio
        if current is not None and current_radio is not None:
            bssid = current_radio.get("bssid")
            if bssid:
                current.bssids.append(current_radio)
            else:
                current.orphan_bssids.append(current_radio)
        current_radio = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        match = _KEY_VALUE_PATTERN.match(line)
        if not match:
            continue

        key = match.group("key").strip()
        value = match.group("value").strip()

        if _SSID_KEY_PATTERN.match(key):
            close_radio()
            current = ParsedNetwork(ssid=_clean(value))
            networks.append(current)
            continue

        if current is None:
            # Interface banner, "There are N networks ..." and similar lines
            # that appear before the first SSID block.
            continue

        if _BSSID_KEY_PATTERN.match(key):
            close_radio()
            candidate = value.strip() or None
            if candidate is not None and not re.fullmatch(
                r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", candidate
            ):
                logger.debug("dropping malformed BSSID value: %r", candidate)
                candidate = None
            current_radio = {"bssid": candidate}
            continue

        if _AUTH_KEY_PATTERN.match(key):
            current.authentication = _clean(value) or current.authentication
            continue
        if _ENCRYPTION_KEY_PATTERN.match(key):
            current.encryption = _clean(value) or current.encryption
            continue

        if _SIGNAL_KEY_PATTERN.match(key):
            if current_radio is not None:
                parsed_signal = _to_signal(value)
                if parsed_signal is not None:
                    current_radio["signal"] = parsed_signal
            continue
        if _CHANNEL_KEY_PATTERN.match(key):
            if current_radio is not None:
                parsed_channel = _to_channel(value)
                if parsed_channel is not None:
                    current_radio["channel"] = parsed_channel
            continue
        # Locale-tolerant recovery: labels translate, value shapes do not.
        # Inside a radio block a percent value is a signal reading and a bare
        # integer is a channel on every locale netsh ships in. Set-once, so
        # an English label that matched first is never overwritten.
        if current_radio is not None:
            if current_radio.get("signal") is None:
                parsed_signal = _to_signal(value)
                if parsed_signal is not None:
                    current_radio["signal"] = parsed_signal
                    continue
            if current_radio.get("channel") is None:
                parsed_channel = _to_channel(value)
                if parsed_channel is not None:
                    current_radio["channel"] = parsed_channel
                    continue
        # Any other label whose value looks like a MAC address is a BSSID.
        if current_radio is None and re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", value):
            close_radio()
            current_radio = {"bssid": value}
            continue

    close_radio()
    return networks


def locale_diagnostic(text: str) -> str | None:
    """Return an honest warning when netsh output uses labels we cannot read.

    Detection is deliberately conservative so it never fires on English
    output: at least one SSID block must be present, none of the three
    frequently translated labels (authentication, encryption, channel) may
    match their English aliases, and several labelled lines inside the
    blocks must have gone unrecognised. Values recovered by shape (BSSID
    MAC addresses, percent signals) do not count as lost labels.
    """
    if not text or not text.strip():
        return None

    seen_ssid = False
    translated_matches = 0
    unrecognised = 0
    for raw_line in text.splitlines():
        match = _KEY_VALUE_PATTERN.match(raw_line.rstrip())
        if not match:
            continue
        key = match.group("key").strip()
        value = match.group("value").strip()
        if _SSID_KEY_PATTERN.match(key):
            seen_ssid = True
            continue
        if not seen_ssid:
            continue
        if (
            _AUTH_KEY_PATTERN.match(key)
            or _ENCRYPTION_KEY_PATTERN.match(key)
            or _CHANNEL_KEY_PATTERN.match(key)
        ):
            translated_matches += 1
            continue
        if _BSSID_KEY_PATTERN.match(key) or _SIGNAL_KEY_PATTERN.match(key):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}", value):
            continue  # BSSID label recovered by shape — not a lost label
        unrecognised += 1

    if seen_ssid and translated_matches == 0 and unrecognised >= 2:
        return (
            "netsh returned network details with unrecognised labels "
            "(non-English Windows output); security details may be incomplete "
            "— see docs/troubleshooting.md"
        )
    return None


def parse_visible_networks_as_observations(
    text: str,
    *,
    observed_at: datetime | None = None,
) -> list[NetworkObservation]:
    """Parse raw scan text directly into :class:`NetworkObservation` models.

    One observation is produced per radio entry; an SSID that reports no
    BSSID still yields a single observation so hidden or partial results are
    not lost.
    """
    stamp = observed_at or utcnow()
    observations: list[NetworkObservation] = []

    for network in parse_visible_networks(text):
        security = network.security_label()
        radios = network.bssids + network.orphan_bssids
        if not radios:
            observations.append(
                NetworkObservation(
                    ssid=network.ssid,
                    security=security,
                    observed_at=stamp,
                )
            )
            continue

        for radio in radios:
            observations.append(
                NetworkObservation(
                    ssid=network.ssid,
                    bssid=radio.get("bssid"),  # type: ignore[arg-type]
                    signal_strength=radio.get("signal"),  # type: ignore[arg-type]
                    security=security,
                    channel=radio.get("channel"),  # type: ignore[arg-type]
                    observed_at=stamp,
                )
            )

    return observations
