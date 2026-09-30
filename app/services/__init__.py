"""Long-running services such as the periodic monitoring loop.

Phase 5 will add the monitoring service with a start/stop lifecycle that never
overlaps scans and never blocks the GUI thread.
"""

from __future__ import annotations

__all__: list[str] = []
