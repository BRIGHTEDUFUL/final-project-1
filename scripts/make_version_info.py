"""Regenerate the Windows version resource text file for the executable.

Writes ``assets/file_version_info.txt``: PyInstaller's text serialization of
a ``VSVersionInfo`` structure. ``rogue-ap-hunter.spec`` passes it to the EXE
``version=`` argument, so Explorer and the file properties dialog show the
file/product version of the built executable.

The version numbers come from ``project.version`` in ``pyproject.toml`` so
there is a single source of truth: bump that, then regenerate this file.

Usage
-----
``.\\.venv\\Scripts\\python.exe scripts\\make_version_info.py``
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from PyInstaller.utils.win32 import versioninfo

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "assets" / "file_version_info.txt"

COMPANY = "Rogue AP Hunter contributors"
DESCRIPTION = "Offline-first Wi-Fi rogue access point monitoring for Windows"
PRODUCT = "Rogue AP Hunter"
INTERNAL_NAME = "RogueAPHunter"
ORIGINAL_FILENAME = "RogueAPHunter.exe"


def _version_tuple() -> tuple[int, int, int, int]:
    """Read ``project.version`` from pyproject.toml as a 4-part Windows tuple."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    parts = str(data["project"]["version"]).split(".")
    numbers = [int(part) for part in parts[:4]] + [0, 0, 0]
    return numbers[0], numbers[1], numbers[2], numbers[3]


def main() -> None:
    """Write the version resource text file and verify it round-trips."""
    version = _version_tuple()
    dotted = ".".join(str(part) for part in version)
    info = versioninfo.VSVersionInfo(
        ffi=versioninfo.FixedFileInfo(filevers=version, prodvers=version),
        kids=[
            versioninfo.StringFileInfo(
                [
                    versioninfo.StringTable(
                        "040904B0",  # en-US, Unicode
                        [
                            versioninfo.StringStruct("CompanyName", COMPANY),
                            versioninfo.StringStruct("FileDescription", DESCRIPTION),
                            versioninfo.StringStruct("FileVersion", dotted),
                            versioninfo.StringStruct("InternalName", INTERNAL_NAME),
                            versioninfo.StringStruct("OriginalFilename", ORIGINAL_FILENAME),
                            versioninfo.StringStruct("ProductName", PRODUCT),
                            versioninfo.StringStruct("ProductVersion", dotted),
                        ],
                    )
                ]
            ),
            versioninfo.VarFileInfo([versioninfo.VarStruct("Translation", [1033, 1200])]),
        ],
    )
    TARGET.write_text(str(info) + "\n", encoding="utf-8")
    # Round-trip through the loader PyInstaller itself uses: a malformed file
    # would raise here instead of failing much later inside a release build.
    versioninfo.load_version_info_from_text_file(str(TARGET))
    print(f"wrote {TARGET} (version {dotted})")


if __name__ == "__main__":
    main()
