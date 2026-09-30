"""Regenerate the application icon: ``assets/icon.png`` and ``assets/icon.ico``.

Development tool only. It draws the same RF mark the sidebar uses (an emitter
dot with three broadcast arcs, see ``app.ui.widgets.SignalMark``) on a graphite
tile, renders it straight from vector geometry at every size Windows expects,
and packs the renders into a PNG-compressed ``.ico`` container (supported since
Windows Vista, and accepted by PyInstaller, which copies icon blobs as-is).

Usage
-----
``.\\.venv\\Scripts\\python.exe scripts\\make_icon.py``
"""

from __future__ import annotations

import struct
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPen

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"

ACCENT = "#3ab7c9"  # app.ui.theme.ACCENT
GRAPHITE = "#0f141a"  # app.ui.theme.GRAPHITE
LINE = "#232c38"  # app.ui.theme.LINE

DESIGN = 512  # logical canvas; every pixel size scales from these numbers
ICO_SIZES = (16, 32, 48, 64, 128, 256)

# SignalMark's 24-box geometry, scaled and translated so the mark's visual
# bounding box sits centred on the tile.
_MARK_SCALE = 18.0
_ORIGIN = QPointF(147.1, 364.9)
_ARC_RADII = (5.5, 9.5, 13.5)
_PEN_WIDTH = 1.6
_DOT_RADIUS = 2.2


def _draw_tile(painter: QPainter, size: int) -> None:
    """Paint the rounded tile and the RF mark at exactly ``size`` pixels."""
    k = size / DESIGN
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    # Tile: graphite rounded square with a hairline edge. The edge is drawn
    # inside the canvas (pen centred on an inset rectangle) so nothing clips.
    border = max(1.0, 16.0 * k)
    rect = QRectF(border / 2.0, border / 2.0, size - border, size - border)
    painter.setPen(QPen(QColor(LINE), border))
    painter.setBrush(QColor(GRAPHITE))
    painter.drawRoundedRect(rect, 112 * k, 112 * k)

    # RF mark: three arcs sweeping a quarter turn around the emitter dot.
    origin = QPointF(_ORIGIN.x() * k, _ORIGIN.y() * k)
    painter.setPen(
        QPen(
            QColor(ACCENT),
            _PEN_WIDTH * _MARK_SCALE * k,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
        )
    )
    painter.setBrush(Qt.BrushStyle.NoBrush)
    for radius in _ARC_RADII:
        r = radius * _MARK_SCALE * k
        painter.drawArc(QRectF(origin.x() - r, origin.y() - r, 2 * r, 2 * r), 0, 90 * 16)
    painter.setBrush(QColor(ACCENT))
    painter.setPen(Qt.PenStyle.NoPen)
    dot = _DOT_RADIUS * _MARK_SCALE * k
    painter.drawEllipse(origin, dot, dot)


def _render(size: int) -> QImage:
    """Render one transparent-background tile of ``size`` × ``size`` pixels."""
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    _draw_tile(painter, size)
    painter.end()
    return image


def _png_bytes(image: QImage) -> bytes:
    """Encode a rendered image as PNG in memory."""
    buffer = QBuffer()
    if not buffer.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError("could not open an in-memory buffer for PNG encoding")
    try:
        if not image.save(buffer, "PNG"):
            raise OSError("PNG encoding failed")
        return bytes(buffer.data())
    finally:
        buffer.close()


def _ico(pngs: dict[int, bytes]) -> bytes:
    """Pack PNG payloads into a PNG-compressed .ico container."""
    entries = sorted(pngs.items())
    directory = bytearray()
    blobs = bytearray()
    offset = 6 + 16 * len(entries)  # ICONDIR header, then 16 bytes per entry
    for size, data in entries:
        dim = size if size < 256 else 0  # an ICONDIRENTRY encodes 256 as 0
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    header = struct.pack("<HHH", 0, 1, len(entries))  # reserved, type icon, count
    return header + bytes(directory) + bytes(blobs)


def main() -> None:
    """Write ``assets/icon.png`` (256 px) and ``assets/icon.ico`` (16-256 px)."""
    ASSETS.mkdir(parents=True, exist_ok=True)
    pngs = {size: _png_bytes(_render(size)) for size in ICO_SIZES}
    icon_png = ASSETS / "icon.png"
    icon_ico = ASSETS / "icon.ico"
    icon_png.write_bytes(pngs[256])
    icon_ico.write_bytes(_ico(pngs))
    sizes = ", ".join(str(size) for size in ICO_SIZES)
    print(f"wrote {icon_png} and {icon_ico} (ico sizes: {sizes} px)")


if __name__ == "__main__":
    main()
