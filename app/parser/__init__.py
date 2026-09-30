"""Parsing and normalisation of raw scanner output into domain observations.

Parsers are pure functions over text: no subprocess, no database, no GUI.
"""

from __future__ import annotations

from app.parser.interfaces import InterfaceInfo, parse_interfaces
from app.parser.netsh_networks import (
    ParsedNetwork,
    parse_visible_networks,
    parse_visible_networks_as_observations,
)

__all__ = [
    "InterfaceInfo",
    "ParsedNetwork",
    "parse_interfaces",
    "parse_visible_networks",
    "parse_visible_networks_as_observations",
]
