"""Unit tests for the command line parser."""

from __future__ import annotations

import pytest

from app.main import build_parser


def test_parser_accepts_no_arguments() -> None:
    args = build_parser().parse_args([])
    assert args.headless is False
    assert args.config is None
    assert args.log_level is None


def test_parser_accepts_headless_and_log_level() -> None:
    args = build_parser().parse_args(["--headless", "--log-level", "DEBUG"])
    assert args.headless is True
    assert args.log_level == "DEBUG"


def test_parser_rejects_unknown_log_level() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--log-level", "TRACE"])


def test_parser_requires_known_config_path_type() -> None:
    args = build_parser().parse_args(["--config", "custom.json"])
    assert args.config.name == "custom.json"
