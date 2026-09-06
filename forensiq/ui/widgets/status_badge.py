"""
forensiq/ui/widgets/status_badge.py
-------------------------------------
Reusable status badge widget — a coloured pill label.

Phase 1: Implemented.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel


class StatusBadge(QLabel):
    """
    A small coloured pill label used to show status across the UI.
    Object name determines the QSS styling applied.

    Supported statuses:
      VERIFIED   → green  (badge_verified)
      VALID      → green
      ACTIVE     → green
      PENDING    → amber  (badge_pending)
      WARNING    → amber
      UNKNOWN    → amber
      PARTIAL    → amber
      ERROR      → red    (badge_error)
      INVALID    → red
      FAILED     → red
      MISMATCH   → red
      EXPERIMENTAL → amber (badge_experimental)
      PLACEHOLDER  → grey (badge_placeholder)
      TESTED       → green
      PLANNED      → grey
    """

    _STATUS_MAP = {
        "VERIFIED":     "badge_verified",
        "VALID":        "badge_verified",
        "ACTIVE":       "badge_verified",
        "CONFIRMED":    "badge_verified",
        "TESTED":       "badge_verified",
        "WORKING_COPY_READY": "badge_verified",
        "PENDING":      "badge_pending",
        "WARNING":      "badge_pending",
        "UNKNOWN":      "badge_pending",
        "PARTIAL":      "badge_pending",
        "NEEDS_REVIEW": "badge_pending",
        "NOT_ATTEMPTED":"badge_pending",
        "EXPERIMENTAL": "badge_experimental",
        "ERROR":        "badge_error",
        "INVALID":      "badge_error",
        "FAILED":       "badge_error",
        "MISMATCH":     "badge_error",
        "INVALID_EVENT_HASH":    "badge_error",
        "INVALID_PREVIOUS_LINK": "badge_error",
        "MISSING_EVENT":         "badge_error",
        "REJECTED":     "badge_error",
        "EMPTY_CHAIN":  "badge_pending",
        "PLACEHOLDER":  "badge_placeholder",
        "PLANNED":      "badge_placeholder",
        "CLOSED":       "badge_placeholder",
        "ARCHIVED":     "badge_placeholder",
        "UNSUPPORTED":  "badge_placeholder",
        "SAFE_FAILURE": "badge_placeholder",
    }

    def __init__(self, status: str = "UNKNOWN", parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_status(status)

    def set_status(self, status: str) -> None:
        """Update the badge text and QSS object-name styling."""
        self.setText(status.replace("_", " "))
        name = self._STATUS_MAP.get(status.upper(), "badge_placeholder")
        self.setObjectName(name)
        # Force QSS re-evaluation
        self.style().unpolish(self)
        self.style().polish(self)
