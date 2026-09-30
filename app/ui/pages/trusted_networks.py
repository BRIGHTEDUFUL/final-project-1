"""Trusted networks: the approved baseline used by every detection rule."""

from __future__ import annotations

import logging

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from app.core.context import AppContext
from app.models import InvalidBssidError, ModelValidationError, TrustedNetwork
from app.ui.pages.base import Page
from app.ui.table_models import ColumnTableModel
from app.ui.widgets import styled_table

logger = logging.getLogger(__name__)

__all__ = ["TrustedNetworksPage", "TrustedNetworkDialog"]

_SECURITY_OPTIONS = (
    "(not specified)",
    "Open",
    "WEP",
    "WPA",
    "WPA2-Personal",
    "WPA3-SAE",
    "WPA2-Enterprise",
    "WPA3-Enterprise",
)


class TrustedNetworkDialog(QDialog):
    """Create or edit one trusted network profile."""

    def __init__(
        self,
        profile: TrustedNetwork | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit trusted network" if profile else "Add trusted network")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(10)

        self._ssid = QLineEdit(profile.ssid if profile else "")
        self._ssid.setPlaceholderText("Exact network name, e.g. Corporate")
        form.addRow("SSID", self._ssid)

        self._bssids = QPlainTextEdit(
            "\n".join(profile.approved_bssids) if profile else ""
        )
        self._bssids.setPlaceholderText(
            "One BSSID per line (aa:bb:cc:dd:ee:ff).\nLeave empty if only the name is known."
        )
        self._bssids.setMaximumHeight(120)
        form.addRow("Approved BSSIDs", self._bssids)

        self._security = QComboBox()
        self._security.addItems(_SECURITY_OPTIONS)
        current = profile.expected_security if profile and profile.expected_security else None
        if current and current not in _SECURITY_OPTIONS:
            self._security.addItem(current)
        self._security.setCurrentText(current if current else "(not specified)")
        form.addRow("Expected security", self._security)

        self._notes = QLineEdit(profile.notes if profile else "")
        self._notes.setPlaceholderText("Optional operator note")
        form.addRow("Notes", self._notes)

        layout.addLayout(form)

        self._error = QLabel("")
        self._error.setWordWrap(True)
        self._error.setStyleSheet("color: #e04f4f;")
        self._error.setVisible(False)
        layout.addWidget(self._error)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._validated_profile: TrustedNetwork | None = None

    def _validate(self) -> None:
        bssids = tuple(
            line.strip() for line in self._bssids.toPlainText().splitlines() if line.strip()
        )
        security_text = self._security.currentText()
        try:
            profile = TrustedNetwork(
                ssid=self._ssid.text(),
                approved_bssids=bssids,
                expected_security=None if security_text == "(not specified)" else security_text,
                notes=self._notes.text(),
            )
        except (ModelValidationError, InvalidBssidError) as exc:
            self._error.setText(str(exc))
            self._error.setVisible(True)
            return
        self._validated_profile = profile
        self.accept()

    def profile(self) -> TrustedNetwork | None:
        """The validated profile, available after ``exec()`` returns Accepted."""
        return self._validated_profile

    def prefill_ssid(self, ssid: str) -> None:
        """Set the SSID field before showing the dialog."""
        self._ssid.setText(ssid)


class TrustedNetworksPage(Page):
    """Manage the approved baseline."""

    #: Emitted after any change so other screens can refresh.
    changed = Signal()

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(
            "Trusted networks",
            "Approval baseline: detection rules compare observations against these profiles. "
            "Mesh and enterprise networks legitimately broadcast one name from several radios, "
            "so register every approved BSSID.",
            parent,
        )
        self._context = context

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self._add_button = QPushButton("Add network")
        self._add_button.setObjectName("primaryButton")
        self._add_button.clicked.connect(self._add)
        self._edit_button = QPushButton("Edit")
        self._edit_button.setObjectName("secondaryButton")
        self._edit_button.clicked.connect(self._edit)
        self._delete_button = QPushButton("Remove")
        self._delete_button.setObjectName("secondaryButton")
        self._delete_button.clicked.connect(self._delete)
        self._count_label = QLabel("0 networks")
        self._count_label.setStyleSheet("color: #8b95a3;")

        toolbar.addWidget(self._add_button)
        toolbar.addWidget(self._edit_button)
        toolbar.addWidget(self._delete_button)
        toolbar.addStretch(1)
        toolbar.addWidget(self._count_label)
        self.body.addLayout(toolbar)

        self._model = ColumnTableModel(
            [
                ("SSID", lambda p: p.ssid, None),
                (
                    "Approved BSSIDs",
                    lambda p: ", ".join(p.approved_bssids) if p.approved_bssids else None,
                    lambda p: "\n".join(p.approved_bssids) or "no BSSIDs registered",
                ),
                ("Expected security", lambda p: p.expected_security, None),
                (
                    "Created",
                    lambda p: p.created_at.strftime("%Y-%m-%d"),
                    lambda p: p.created_at.isoformat(),
                ),
                ("Notes", lambda p: p.notes, None),
            ]
        )
        self._table = styled_table(self._model)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.body.addWidget(self._table)

        hint = QLabel(
            "Tip: select your own network here to teach the engine what 'normal' looks like. "
            "Without a baseline, only structural indicators (duplicate names, unusual signal) can fire."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6b7482; font-size: 12px;")
        self.body.addWidget(hint)

    # ----------------------------------------------------------------- data

    def refresh(self) -> None:
        """Reload profiles from storage."""
        profiles = self._context.trusted.list()
        self._model.set_rows(profiles)
        self._count_label.setText(
            f"{len(profiles)} network{'s' if len(profiles) != 1 else ''}"
        )

    # ------------------------------------------------------------ actions

    def _add(self) -> None:
        dialog = TrustedNetworkDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        profile = dialog.profile()
        if profile is None:
            return
        try:
            self._context.trusted.upsert(profile)
        except Exception as exc:
            logger.exception("could not save trusted network")
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self._after_change(f"'{profile.ssid}' added to the baseline.")

    def _edit(self) -> None:
        profile = self._selected()
        if profile is None:
            QMessageBox.information(self, "No network selected", "Select a network first.")
            return
        dialog = TrustedNetworkDialog(profile, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        updated = dialog.profile()
        if updated is None:
            return
        self._context.trusted.upsert(updated)
        self._after_change(f"'{updated.ssid}' updated.")

    def _delete(self) -> None:
        profile = self._selected()
        if profile is None:
            QMessageBox.information(self, "No network selected", "Select a network first.")
            return
        answer = QMessageBox.question(
            self,
            "Remove trusted network",
            f"Remove '{profile.ssid}' from the approved baseline?\n\n"
            "Future observations of this name will be treated as unknown.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        if profile.id is not None:
            self._context.trusted.delete(profile.id)
        else:
            self._context.trusted.delete_by_ssid(profile.ssid)
        self._after_change(f"'{profile.ssid}' removed from the baseline.")

    def _selected(self) -> TrustedNetwork | None:
        indexes = self._table.selectionModel().selectedRows()
        if not indexes:
            return None
        return self._model.row_at(indexes[0].row())

    def _after_change(self, message: str) -> None:
        self.refresh()
        self.changed.emit()
        self.window().statusBar().showMessage(message, 6000)  # type: ignore[union-attr]
