"""Command line entry point for Rogue AP Hunter.

Exit codes
----------
``0`` success, ``1`` unexpected runtime failure, ``2`` invalid arguments
(argparse default), ``3`` the graphical interface could not be started.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from app import APP_NAME, VERSION
from app.core import paths
from app.core.config import Config, ConfigError, load_config, save_config
from app.core.logging_setup import setup_logging

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_GUI_UNAVAILABLE = 3

__all__ = [
    "EXIT_FAILURE",
    "EXIT_GUI_UNAVAILABLE",
    "EXIT_OK",
    "EXIT_USAGE",
    "build_parser",
    "main",
    "run",
]


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        prog="rogue-ap-hunter",
        description=(
            "Live Wi-Fi rogue access point detection and alert system. "
            "Passive, defensive and offline-first."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {VERSION}",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="initialise configuration and logging, then exit without opening the window",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="use an explicit configuration file instead of the per-user default",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default=None,
        help="override the configured logging level",
    )
    parser.add_argument(
        "--write-default-config",
        action="store_true",
        help="write the default configuration to the selected file and exit",
    )
    return parser


def _load_configuration(config_path: Path | None) -> Config:
    """Load configuration, falling back to defaults with a loud warning."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        logger.error("Configuration could not be loaded (%s); using built-in defaults.", exc)
        return Config()
    return config


def main(argv: Sequence[str] | None = None) -> int:
    """Run the application and return a process exit code."""
    args = build_parser().parse_args(argv)

    level = args.log_level or "INFO"
    if args.config is None:
        paths.ensure_app_dirs()
    else:
        args.config.parent.mkdir(parents=True, exist_ok=True)
    setup_logging(level, console=True, force=True)

    config = _load_configuration(args.config)

    if args.write_default_config:
        try:
            target = save_config(config, args.config)
        except ConfigError as exc:
            logger.error("Could not write configuration: %s", exc)
            return EXIT_FAILURE
        logger.info("Default configuration written to %s", target)
        return EXIT_OK

    logger.info("%s %s starting", APP_NAME, VERSION)
    logger.info(
        "Configuration: scan interval %ss, thresholds L%s/M%s/H%s, notifications %s",
        config.scan_interval_seconds,
        config.suspicious_threshold,
        config.high_threshold,
        config.critical_threshold,
        "on" if config.notifications_enabled else "off",
    )

    if args.headless:
        logger.info("Headless initialisation complete; exiting.")
        return EXIT_OK

    try:
        from app.ui.shell import run_app
    except ImportError as exc:
        logger.error(
            "The graphical interface is unavailable (%s). "
            "Install the UI dependency with 'pip install -e \".[dev]\"' "
            "or run with --headless.",
            exc,
        )
        return EXIT_GUI_UNAVAILABLE

    try:
        return run_app(config)
    except Exception:
        logger.exception("Unhandled error while running the graphical interface")
        return EXIT_FAILURE


def run() -> None:
    """Console-script wrapper for ``rogue-ap-hunter``."""
    sys.exit(main())


if __name__ == "__main__":
    run()
