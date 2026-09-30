"""Shared pytest configuration: fixtures and repository import path."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def load_fixture() -> Callable[[str], str]:
    """Return a loader that reads a sanitized scanner-output fixture."""

    def _load(name: str) -> str:
        path = FIXTURES / name
        assert path.is_file(), f"missing fixture: {name}"
        return path.read_text(encoding="utf-8")

    return _load
