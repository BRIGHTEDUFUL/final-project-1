# Assets

Icons, images and other static resources used by the interface.

Store source artwork here (SVG preferred) and keep binary exports small.
Do not commit licensed third-party artwork without documenting it in
`THIRD_PARTY_LICENSES.md`.

## Shipped files

| File | Used by | Regenerate with |
| --- | --- | --- |
| `icon.png` (256 px) | the main window icon at runtime (`app.ui.shell`) | `.\.venv\Scripts\python.exe scripts\make_icon.py` |
| `icon.ico` (16–256 px) | the Windows executable icon (`rogue-ap-hunter.spec`, `EXE(icon=...)`) | `.\.venv\Scripts\python.exe scripts\make_icon.py` |
| `file_version_info.txt` | the Windows version resource (`rogue-ap-hunter.spec`, `EXE(version=...)`) | `.\.venv\Scripts\python.exe scripts\make_version_info.py` |

Both generators are offline, dependency-free development tools. The icon is
drawn from the same RF mark as `app.ui.widgets.SignalMark` (emitter dot plus
three broadcast arcs) using the theme colours, so re-running the generator
keeps the artwork consistent with the UI. The version resource reads its
numbers from `project.version` in `pyproject.toml` — bump there first, then
regenerate.
