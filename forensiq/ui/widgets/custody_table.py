"""
forensiq/ui/widgets/custody_table.py
--------------------------------------
QTableWidget for displaying chain-of-custody events.

Columns:
  Timestamp UTC | Action | Actor | SHA-256 (out, partial) | Reason

Phase 2: Fully implemented (with max_rows limit for mini-table use).
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from forensiq.models.custody import CustodyEvent

_COLUMNS = ["Timestamp UTC", "Action", "Actor", "Output SHA-256", "Reason"]


class CustodyTable(QWidget):
    """Displays a list of CustodyEvent records."""

    def __init__(self, max_rows: Optional[int] = None, parent=None):
        super().__init__(parent)
        self._max_rows = max_rows

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._empty_label = QLabel("No custody events recorded.")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._empty_label.setStyleSheet("color: #6b7280; font-size: 11px; padding: 12px;")
        layout.addWidget(self._empty_label)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget { background: #0d1821; color: #cdd6e0; "
            "gridline-color: #1e3a5f; border: 1px solid #1e3a5f; border-radius: 4px; }"
            "QHeaderView::section { background: #0a1628; color: #7ec8e3; "
            "border-bottom: 1px solid #1e3a5f; padding: 5px; font-weight: bold; }"
            "QTableWidget::item:alternate { background: #0a1628; }"
            "QTableWidget::item:selected { background: #1e3a5f; }"
        )
        self._table.setVisible(False)
        layout.addWidget(self._table)

    def load(self, events: list[CustodyEvent]) -> None:
        """Populate from a list of CustodyEvent ORM objects."""
        self._table.setRowCount(0)

        if not events:
            self._empty_label.setVisible(True)
            self._table.setVisible(False)
            return

        self._empty_label.setVisible(False)
        self._table.setVisible(True)

        display = events[: self._max_rows] if self._max_rows else events
        for row_idx, ev in enumerate(display):
            self._table.insertRow(row_idx)

            # Timestamp
            ts = "—"
            if ev.action_timestamp_utc:
                ts = ev.action_timestamp_utc.strftime("%Y-%m-%d %H:%M:%S")
            self._set_cell(row_idx, 0, ts)

            # Action
            self._set_cell(row_idx, 1, ev.action or "—")

            # Actor
            self._set_cell(row_idx, 2, ev.actor_id or "—")

            # Output SHA-256 (partial)
            sha = ev.output_sha256 or ""
            self._set_cell(row_idx, 3, sha[:16] + "…" if len(sha) > 16 else sha or "—")

            # Reason
            self._set_cell(row_idx, 4, ev.reason or "—")

        self._table.resizeColumnsToContents()

    def _set_cell(self, row: int, col: int, text: str) -> None:
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._table.setItem(row, col, item)
