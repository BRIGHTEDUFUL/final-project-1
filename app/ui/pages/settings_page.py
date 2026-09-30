"""Settings: scan cadence, thresholds, weights, notifications and retention."""

from __future__ import annotations

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QWidget,
)

from app.core.config import (
    MAX_SCAN_INTERVAL_SECONDS,
    MIN_SCAN_INTERVAL_SECONDS,
    VALID_LOG_LEVELS,
    Config,
    ConfigError,
    RiskWeights,
)
from app.core.context import AppContext
from app.ui.pages.base import Page

logger = logging.getLogger(__name__)

__all__ = ["SettingsPage"]

_WEIGHT_FIELDS = (
    ("duplicate_ssid", "Duplicate SSID"),
    ("unknown_bssid", "Unknown BSSID"),
    ("security_downgrade", "Security downgrade"),
    ("new_access_point", "New access point"),
    ("suspicious_signal", "Suspicious signal"),
    ("persistence", "Persistence"),
)


class SettingsPage(Page):
    """Editable configuration form with validation and save."""

    #: Emitted after settings were stored successfully.
    saved = Signal()

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Settings",
            "Local configuration only \u2014 nothing here is sent anywhere.",
            parent,
        )
        self._context = context

        # ---- monitoring -------------------------------------------------
        monitoring_box = QGroupBox("Monitoring")
        monitoring_form = QFormLayout(monitoring_box)
        self._interval = QSpinBox()
        self._interval.setRange(MIN_SCAN_INTERVAL_SECONDS, MAX_SCAN_INTERVAL_SECONDS)
        self._interval.setSuffix(" s")
        monitoring_form.addRow("Scan interval", self._interval)

        self._retention = QSpinBox()
        self._retention.setRange(1, 3650)
        self._retention.setSuffix(" days")
        monitoring_form.addRow("Data retention", self._retention)

        self._log_level = QComboBox()
        self._log_level.addItems(list(VALID_LOG_LEVELS))
        monitoring_form.addRow("Log level", self._log_level)
        self.body.addWidget(monitoring_box)

        # ---- thresholds -------------------------------------------------
        threshold_box = QGroupBox("Severity thresholds (risk score)")
        threshold_layout = QGridLayout(threshold_box)
        self._suspicious = QSpinBox()
        self._high = QSpinBox()
        self._critical = QSpinBox()
        for spin in (self._suspicious, self._high, self._critical):
            spin.setRange(1, 100)
        threshold_layout.addWidget(QLabel("Suspicious \u2265"), 0, 0)
        threshold_layout.addWidget(self._suspicious, 0, 1)
        threshold_layout.addWidget(QLabel("High \u2265"), 0, 2)
        threshold_layout.addWidget(self._high, 0, 3)
        threshold_layout.addWidget(QLabel("Critical \u2265"), 0, 4)
        threshold_layout.addWidget(self._critical, 0, 5)
        note = QLabel("Low is anything below the suspicious threshold.")
        note.setObjectName("hint")
        threshold_layout.addWidget(note, 1, 0, 1, 6)
        self.body.addWidget(threshold_box)

        # ---- weights ----------------------------------------------------
        weights_box = QGroupBox("Risk weights (research parameters)")
        weights_form = QGridLayout(weights_box)
        self._weight_spins: dict[str, QSpinBox] = {}
        for index, (field_name, caption) in enumerate(_WEIGHT_FIELDS):
            spin = QSpinBox()
            spin.setRange(0, 100)
            spin.setSingleStep(5)
            row, column = divmod(index, 3)
            weights_form.addWidget(QLabel(caption), row * 2, column)
            weights_form.addWidget(spin, row * 2 + 1, column)
            self._weight_spins[field_name] = spin
        weights_note = QLabel(
            "Each distinct rule contributes its weight once per identity, "
            "clamped to a 0\u2013100 total."
        )
        weights_note.setObjectName("hint")
        weights_note.setWordWrap(True)
        weights_form.addWidget(weights_note, 4, 0, 1, 3)
        self.body.addWidget(weights_box)

        # ---- notifications ----------------------------------------------
        notify_box = QGroupBox("Notifications")
        notify_form = QFormLayout(notify_box)
        self._notifications = QCheckBox("Show Windows toast notifications for new alerts")
        notify_form.addRow(self._notifications)
        notify_hint = QLabel(
            "Notifications fire only on new alerts or severity escalations, with a "
            "one-minute cooldown per alert. The in-app alert list is always complete."
        )
        notify_hint.setWordWrap(True)
        notify_hint.setObjectName("hint")
        notify_form.addRow(notify_hint)
        self.body.addWidget(notify_box)

        # ---- frame observer --------------------------------------------
        frame_box = QGroupBox("Passive frame observer")
        frame_form = QFormLayout(frame_box)
        self._frame_enabled = QCheckBox(
            "Analyze beacon frames for extra evidence (requires the Npcap driver)"
        )
        frame_form.addRow(self._frame_enabled)
        self._frame_status = QLabel("")
        self._frame_status.setObjectName("hint")
        self._frame_status.setWordWrap(True)
        frame_form.addRow("Status", self._frame_status)
        frame_note = QLabel(
            "Reads only broadcast beacon and probe-response frames on this machine. "
            "No transmission, no decryption, no client tracking. Without the free "
            "Npcap driver the application stays netsh-only."
        )
        frame_note.setWordWrap(True)
        frame_note.setObjectName("hint")
        frame_form.addRow(frame_note)
        self.body.addWidget(frame_box)

        # ---- actions ----------------------------------------------------
        actions = QHBoxLayout()
        self._save_button = QPushButton("Save settings")
        self._save_button.setObjectName("primaryButton")
        self._save_button.clicked.connect(self._save)
        self._reset_button = QPushButton("Reload")
        self._reset_button.setObjectName("secondaryButton")
        self._reset_button.clicked.connect(self.refresh)
        self._path_label = QLabel(str(self._context.config_path))
        self._path_label.setObjectName("hint")
        actions.addWidget(self._save_button)
        actions.addWidget(self._reset_button)
        actions.addStretch(1)
        actions.addWidget(self._path_label)
        self.body.addLayout(actions)
        self.body.addStretch(1)

        # The form exceeds a short window: make it reachable by scrolling
        # instead of clipping.
        self.make_scrollable()

        self.refresh()

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Populate the form from the current configuration."""
        config = self._context.config
        self._interval.setValue(config.scan_interval_seconds)
        self._retention.setValue(config.data_retention_days)
        self._log_level.setCurrentText(config.log_level)
        self._suspicious.setValue(config.suspicious_threshold)
        self._high.setValue(config.high_threshold)
        self._critical.setValue(config.critical_threshold)
        self._notifications.setChecked(config.notifications_enabled)
        self._frame_enabled.setChecked(config.frame_observer_enabled)
        self._frame_status.setText(self._context.frame_observer.status_text())
        for field_name, spin in self._weight_spins.items():
            spin.setValue(getattr(config.risk_weights, field_name))

    def collect(self) -> Config:
        """Build a validated configuration from the form."""
        return Config(
            scan_interval_seconds=self._interval.value(),
            suspicious_threshold=self._suspicious.value(),
            high_threshold=self._high.value(),
            critical_threshold=self._critical.value(),
            notifications_enabled=self._notifications.isChecked(),
            frame_observer_enabled=self._frame_enabled.isChecked(),
            data_retention_days=self._retention.value(),
            log_level=self._log_level.currentText(),
            risk_weights=RiskWeights(
                **{name: spin.value() for name, spin in self._weight_spins.items()}
            ),
        )

    # ------------------------------------------------------------ actions

    def _save(self) -> None:
        try:
            config = self.collect()
            config.validate()
        except ConfigError as exc:
            QMessageBox.warning(self, "Invalid settings", str(exc))
            return
        try:
            saved_path = self._context.save_config(config)
        except (ConfigError, OSError) as exc:
            logger.exception("settings could not be saved")
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self._path_label.setText(str(saved_path))
        # Reflect any live-state change (e.g. the frame observer starting)
        # that the save just triggered.
        self._frame_status.setText(self._context.frame_observer.status_text())
        self.window().statusBar().showMessage(f"Settings saved to {saved_path}", 6000)  # type: ignore[union-attr]
        self.saved.emit()
