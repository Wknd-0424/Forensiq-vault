"""
forensiq/ui/widgets/hash_card.py
----------------------------------
Widget displaying SHA-256 and MD5 hash values with:
  - Monospace display for the full hex string
  - Copy-to-clipboard button per hash
  - Verified / Mismatch / Unverified status badge
  - Algorithm note label: "MD5 for legacy compatibility only"

Phase 2: Fully implemented.
"""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QApplication,
)


class _HashRow(QWidget):
    """A single hash row: label + monospace value + copy button."""

    def __init__(self, algorithm: str, hex_value: str, note: str = "", parent=None):
        super().__init__(parent)
        self._value = hex_value

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(2)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        # Algorithm label
        algo_label = QLabel(f"<b>{algorithm}</b>")
        algo_label.setFixedWidth(72)
        algo_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        algo_label.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        row.addWidget(algo_label)

        # Hash value (monospace, selectable)
        mono = QFont("Courier New", 10)
        self._value_label = QLabel(hex_value or "—")
        self._value_label.setFont(mono)
        self._value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._value_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._value_label.setStyleSheet(
            "color: #e8f0fe; background: #12181f; "
            "padding: 4px 8px; border-radius: 4px; letter-spacing: 0.5px;"
        )
        row.addWidget(self._value_label)

        # Copy button
        copy_btn = QPushButton("⎘")
        copy_btn.setFixedSize(28, 28)
        copy_btn.setToolTip(f"Copy {algorithm} hash")
        copy_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; "
            "border: 1px solid #2d4a6a; border-radius: 4px; font-size: 14px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        copy_btn.clicked.connect(self._copy_to_clipboard)
        row.addWidget(copy_btn)

        main_layout.addLayout(row)

        if note:
            note_label = QLabel(note)
            note_label.setStyleSheet("color: #6b7280; font-size: 9px; margin-left: 82px;")
            main_layout.addWidget(note_label)

    def _copy_to_clipboard(self) -> None:
        if self._value:
            QApplication.clipboard().setText(self._value)

    def set_value(self, hex_value: str) -> None:
        self._value = hex_value
        self._value_label.setText(hex_value or "—")


class HashCard(QFrame):
    """
    Displays SHA-256 and MD5 for an evidence item.

    Includes:
    - SHA-256 row (primary)
    - MD5 row with "legacy compatibility" note
    - A status badge: VERIFIED (green) / MISMATCH (red) / UNVERIFIED (grey)
    """

    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    UNVERIFIED = "UNVERIFIED"

    _STATUS_STYLES = {
        VERIFIED:   "background:#1a4731; color:#34d399; border:1px solid #059669;",
        MISMATCH:   "background:#4a1a1a; color:#f87171; border:1px solid #dc2626;",
        UNVERIFIED: "background:#1e2d3d; color:#9aa5b4; border:1px solid #374151;",
    }

    def __init__(
        self,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(
            "HashCard { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; }"
        )

        main = QVBoxLayout(self)
        main.setContentsMargins(16, 12, 16, 12)
        main.setSpacing(10)

        # Header row
        header = QHBoxLayout()
        title = QLabel("🔐 Integrity Hashes")
        title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 13px;")
        header.addWidget(title)
        header.addStretch()

        self._status_badge = QLabel(self.UNVERIFIED)
        self._status_badge.setStyleSheet(
            f"{self._STATUS_STYLES[self.UNVERIFIED]} "
            "padding: 2px 10px; border-radius: 10px; font-size: 10px; font-weight: bold;"
        )
        self._status_badge.setAlignment(Qt.AlignCenter)
        header.addWidget(self._status_badge)
        main.addLayout(header)

        # SHA-256 row
        self._sha256_row = _HashRow("SHA-256", sha256 or "", parent=self)
        main.addWidget(self._sha256_row)

        # MD5 row with note
        self._md5_row = _HashRow(
            "MD5", md5 or "",
            note="MD5 for legacy compatibility only. SHA-256 is primary.",
            parent=self,
        )
        main.addWidget(self._md5_row)

    def set_hashes(self, sha256: str, md5: str) -> None:
        """Update displayed hash values."""
        self._sha256_row.set_value(sha256)
        self._md5_row.set_value(md5)
        self.set_status(self.UNVERIFIED)

    def set_status(self, status: str) -> None:
        """Set badge status: VERIFIED, MISMATCH, or UNVERIFIED."""
        style = self._STATUS_STYLES.get(status, self._STATUS_STYLES[self.UNVERIFIED])
        self._status_badge.setText(status)
        self._status_badge.setStyleSheet(
            f"{style} padding: 2px 10px; border-radius: 10px; "
            "font-size: 10px; font-weight: bold;"
        )
