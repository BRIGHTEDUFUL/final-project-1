# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for Rogue AP Hunter.

Build modes (controlled by environment variables, see scripts/build.ps1):

``ROGUE_AP_HUNTER_CONSOLE=1``   attach a console window (useful for CLI use and
                               debugging; default is a windowed GUI build).
``ROGUE_AP_HUNTER_ONEFILE=1``   produce a single executable instead of a
                               directory bundle (default is onedir, which
                               starts faster and upsets antivirus less).

The build is fully offline: only the interpreter, the project and the
dependencies already installed in the virtual environment are used.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(SPECPATH)  # noqa: F821 - SPECPATH is injected by PyInstaller

CONSOLE = os.environ.get("ROGUE_AP_HUNTER_CONSOLE") == "1"
ONEFILE = os.environ.get("ROGUE_AP_HUNTER_ONEFILE") == "1"
APP_NAME = "RogueAPHunter"

# Data shipped next to the code inside the bundle.
datas = [
    (str(ROOT / "assets"), "assets"),
    (str(ROOT / "LICENSE"), "."),
    (str(ROOT / "THIRD_PARTY_LICENSES.md"), "."),
]
docs_dir = ROOT / "docs"
if docs_dir.is_dir():
    datas.append((str(docs_dir), "docs"))

hiddenimports = [
    # Matplotlib's Qt canvas is imported lazily by the investigation screen.
    "matplotlib.backends.backend_qtagg",
    "matplotlib.backends.backend_agg",
]

analysis = Analysis(
    [str(ROOT / "app" / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Unused matplotlib/GUI backends keep the bundle smaller.
        "matplotlib.backends.backend_tkagg",
        "matplotlib.backends.backend_qt5agg",
        "tkinter",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)

if ONEFILE:
    exe = EXE(
        pyz,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        name=APP_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=CONSOLE,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        analysis.scripts,
        [],
        exclude_binaries=True,
        name=APP_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=CONSOLE,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        analysis.binaries,
        analysis.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name=APP_NAME,
    )
