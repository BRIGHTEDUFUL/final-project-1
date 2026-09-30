"""Scanner adapters that read wireless information from the operating system.

Phase 1 will add the Windows ``netsh wlan`` adapter. Adapters only collect raw
output; parsing and interpretation live in :mod:`app.parser`.
"""

from __future__ import annotations

__all__: list[str] = []
