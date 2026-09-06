"""
forensiq/ui/widgets/warning_panel.py
--------------------------------------
Warning, error and info banner widgets used throughout the UI.

Phase 1: Implemented.
"""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel


class WarningPanel(QFrame):
    """Amber warning banner for non-critical notices."""

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setObjectName("warning_panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        icon = QLabel("⚠", self)
        icon.setObjectName("warning_text")
        icon.setFixedWidth(20)
        label = QLabel(text, self)
        label.setObjectName("warning_text")
        label.setWordWrap(True)
        layout.addWidget(icon)
        layout.addWidget(label, stretch=1)


class ErrorPanel(QFrame):
    """Red error banner for critical issues."""

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setObjectName("error_panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        icon = QLabel("✖", self)
        icon.setObjectName("error_text")
        icon.setFixedWidth(20)
        label = QLabel(text, self)
        label.setObjectName("error_text")
        label.setWordWrap(True)
        layout.addWidget(icon)
        layout.addWidget(label, stretch=1)


class InfoPanel(QFrame):
    """Blue info banner for neutral information."""

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setObjectName("info_panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        icon = QLabel("ℹ", self)
        icon.setObjectName("info_text")
        icon.setFixedWidth(20)
        label = QLabel(text, self)
        label.setObjectName("info_text")
        label.setWordWrap(True)
        layout.addWidget(icon)
        layout.addWidget(label, stretch=1)


class DisclaimerPanel(WarningPanel):
    """
    The mandatory AI/hash disclaimer panel shown on relevant pages.
    Content is defined in constants.py — never edited here.
    """

    def __init__(self, parent=None):
        from forensiq.constants import MANDATORY_DISCLAIMER
        super().__init__(MANDATORY_DISCLAIMER, parent)
