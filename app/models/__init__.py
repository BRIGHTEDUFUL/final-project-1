"""Domain models shared across the application.

Models are immutable value objects, independent of both the GUI and the
scanner, and safe against missing or malformed input:

* :class:`NetworkObservation` — one sighting of a wireless network.
* :class:`TrustedNetwork` — the approved baseline profile.
* :class:`Alert` — an explainable security event.
* :class:`ScanSession` — the lifecycle record of a monitoring run.
* :class:`ApplicationSetting` — a persisted key/value preference.

BSSID values are always normalised to ``aa:bb:cc:dd:ee:ff``; missing optional
fields become ``None`` instead of raising, while malformed values raise
:class:`ModelValidationError`.
"""

from __future__ import annotations

from app.models.alert import Alert, AlertStatus, AlertType, Severity
from app.models.base import ModelValidationError, utcnow
from app.models.bssid import InvalidBssidError, normalize_bssid, normalize_bssid_list
from app.models.observation import NetworkObservation
from app.models.security import SecurityMode, classify_security, is_enterprise_security
from app.models.session import ScanSession, ScanSessionStatus
from app.models.setting import ApplicationSetting
from app.models.trusted import TrustedNetwork

__all__ = [
    "Alert",
    "AlertStatus",
    "AlertType",
    "ApplicationSetting",
    "InvalidBssidError",
    "ModelValidationError",
    "NetworkObservation",
    "ScanSession",
    "ScanSessionStatus",
    "SecurityMode",
    "Severity",
    "TrustedNetwork",
    "classify_security",
    "is_enterprise_security",
    "normalize_bssid",
    "normalize_bssid_list",
    "utcnow",
]
