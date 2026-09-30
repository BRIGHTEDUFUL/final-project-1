"""About: version, scope and legal/ethical notice."""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from app.core import paths
from app.ui.pages.base import Page

__all__ = ["AboutPage"]

try:
    VERSION = metadata.version("rogue-ap-hunter")
except metadata.PackageNotFoundError:  # pragma: no cover - running from source
    VERSION = "0.1.0+dev"

BODY = f"""
<p style="color:#f2f5f9; font-size:16px;"><b>Rogue AP Hunter {VERSION}</b></p>
<p>A free, open-source, offline-first desktop tool for passive Wi-Fi monitoring.
It observes the wireless environment through the operating system's own scan
command, compares what it sees against a baseline <i>you</i> approve, and
explains every score it produces.</p>

<p style="color:#e0a63a;"><b>What it does not do</b></p>
<ul>
<li>No credential capture, interception, decryption or man-in-the-middle.</li>
<li>No jamming, deauthentication, packet injection or auto-connect.</li>
<li>No cloud services, paid APIs or telemetry \u2014 everything stays on this PC.</li>
<li>Read-only scanning: settings are never modified by the scanner.</li>
</ul>

<p style="color:#e0a63a;"><b>How to read its output</b></p>
<p>An alert means <i>a pattern you should verify</i>, never proof of an attack.
Legitimate mesh and enterprise networks broadcast one name from many radios,
and a low signal can be environmental. Treat alerts as leads for investigation,
and act only against equipment you own or are authorised to assess.</p>

<p style="color:#e0a63a;"><b>Authorisation notice</b></p>
<p>Use this tool only on networks and premises you own or have explicit
permission to assess. Unauthorised monitoring of other people's networks may
be illegal where you live.</p>

<p style="color:#8b95a3;">
Licence: MIT \u00b7 Data directory: {paths.app_home()}<br/>
Configuration: {paths.config_path()}<br/>
Third-party notices: THIRD_PARTY_LICENSES.md in the installation folder.
</p>
"""


class AboutPage(Page):
    """Version, scope and responsible-use notice."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            "About",
            "Scope, limitations and where data is stored.",
            parent,
        )
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 4, 8, 8)
        text = QLabel(BODY)
        text.setWordWrap(True)
        text.setTextFormat(Qt.TextFormat.RichText)
        text.setOpenExternalLinks(False)
        text.setStyleSheet("color: #d7dde5; font-size: 13px; line-height: 150%;")
        text.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(text)
        layout.addStretch(1)

        scroll.setWidget(content)
        self.body.addWidget(scroll, 1)

    @staticmethod
    def licence_file() -> Path | None:
        """Locate the bundled MIT licence, when present."""
        candidate = Path(__file__).resolve().parents[3] / "LICENSE"
        return candidate if candidate.is_file() else None
