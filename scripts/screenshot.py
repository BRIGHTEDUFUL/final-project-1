r"""Render one page of the application to a PNG for design review.

Development tool only: it builds the real application window (using the normal
per-user data directory), optionally runs one scan so the screens are not
empty, and grabs the widget to an image.

Usage
-----
    .\.venv\Scripts\python.exe scripts\screenshot.py --page dashboard
    .\.venv\Scripts\python.exe scripts\screenshot.py --page investigation --scan
    .\.venv\Scripts\python.exe scripts\screenshot.py --page live --out build\shots\live.png
    .\.venv\Scripts\python.exe scripts\screenshot.py --page about --windowed

Captures run on Qt's *offscreen* platform by default: it renders text only if
Qt is pointed at the Windows font directory, it never flashes a window on the
desktop, and — unlike a real window — it always repaints before the grab (a
visible window that loses exposure hands back a stale frame). Pass
``--windowed`` to capture through a real on-screen window instead.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WINDOWS_FONTS = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "Fonts"

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.core.config import Config  # noqa: E402
from app.core.context import AppContext  # noqa: E402
from app.ui.shell import NAV_ITEMS, MainWindow  # noqa: E402
from app.ui.theme import apply_theme  # noqa: E402

DEFAULT_PAGES = tuple(key for key, _label in NAV_ITEMS)


def _pump(application: QApplication, seconds: float) -> None:
    """Let the event loop settle for a moment without blocking Qt."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.02)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page", default="dashboard", choices=list(DEFAULT_PAGES))
    parser.add_argument("--out", default=str(ROOT / "build" / "shots" / "page.png"))
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=900)
    parser.add_argument("--scan", action="store_true", help="run one real scan first")
    parser.add_argument(
        "--windowed",
        action="store_true",
        help="capture through a real on-screen window instead of the offscreen platform",
    )
    args = parser.parse_args()

    if not args.windowed:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        if WINDOWS_FONTS.is_dir():
            os.environ.setdefault("QT_QPA_FONTDIR", str(WINDOWS_FONTS))

    application = QApplication(sys.argv[:1])
    apply_theme(application)

    context = AppContext(config_path=None, config=Config())
    window = MainWindow(context)
    window.resize(args.width, args.height)
    window.show()
    _pump(application, 1.0)

    if args.scan:
        window.scan_once()
        _pump(application, 1.0)

    window.show_page(args.page)
    _pump(application, 1.5)
    print(f"requested page {args.page!r}, window is on {window.current_page_key()!r}")

    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    image = window.grab()
    if not image.save(str(target)):
        raise SystemExit(f"could not write {target}")
    print(f"wrote {target} ({image.width()}x{image.height()})")

    context.close()
    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
