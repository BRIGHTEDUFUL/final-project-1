# Third-Party Licenses

Rogue AP Hunter itself is released under the MIT License (see `LICENSE`).

The baseline runtime and development stack is composed entirely of free and
open-source components, or functionality already included with Windows.
No paid API, subscription, cloud service or proprietary SDK is required.

## Runtime dependencies

| Component | Purpose | License |
|-----------|---------|---------|
| Python 3 | Programming language | PSF License Agreement |
| PySide6 (Qt for Python) | Desktop user interface | LGPL-3.0-only / GPL-3.0-only with Qt licensing exception |
| Matplotlib | Charts and plots | BSD-3-Clause-like (matplotlib license) |
| Qt (bundled with PySide6) | Graphics toolkit used by PySide6 | LGPL-3.0-only |

PySide6 is the free and open-source Qt binding for Python. Shipping a
PySide6-based application under these terms is permitted; applications that
dynamically link Qt remain subject to LGPL obligations when redistributed.
Read the official PySide6 and Qt licensing notes before publishing binaries:

- https://doc.qt.io/qtforpython/licensing.html

## Development dependencies

| Component | Purpose | License |
|-----------|---------|---------|
| pytest | Automated testing | MIT License |
| ruff | Linting and code quality | MIT License |
| Git | Version control | GPL-2.0-only |
| PyInstaller (optional, packaging phase) | Windows executable packaging | GPL-2.0-only with linking exception |

## Platform functionality (not a library dependency)

| Component | Purpose | Notes |
|-----------|---------|-------|
| Windows `netsh wlan` | Wi-Fi scan data | Included with Windows 10/11; invoked read-only, never used to change network settings |

## Data and network policy

- No telemetry, crash reporting or analytics are transmitted.
- No external threat-intelligence API is queried.
- All observations, alerts and settings are stored locally in SQLite.

If a dependency is added or replaced, update this file in the same commit.
