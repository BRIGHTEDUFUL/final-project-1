"""Long-running services: the monitoring loop that drives the whole pipeline.

Services coordinate repositories, detection and alerts. They contain no GUI
code; the interface layer subscribes to callbacks (or signals) instead.
"""

from __future__ import annotations

from app.services.monitoring import MonitoringService, ScanPipeline, ScanReport

__all__ = ["MonitoringService", "ScanPipeline", "ScanReport"]
