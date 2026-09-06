"""
forensiq/ui/widgets/evidence_table.py
---------------------------------------
QTableWidget showing the evidence items for the currently active case.

Columns:
  # | Evidence # | Filename | Status | SHA-256 (first 16 chars) | Size | Imported At

Signals:
  evidence_selected(evidence_id: str) — emitted when a row is double-clicked.

Phase 2: Fully implemented.
"""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from forensiq.constants import EvidenceStatus
from forensiq.models.evidence import EvidenceItem


_STATUS_COLORS = {
    EvidenceStatus.IMPORTED.value:          ("#3b82f6", "#1e3a5f"),
    EvidenceStatus.HASHED.value:            ("#f59e0b", "#3b2a0e"),
    EvidenceStatus.PRESERVED.value:         ("#8b5cf6", "#2d1f4a"),
    EvidenceStatus.WORKING_COPY_READY.value: ("#34d399", "#1a4731"),
    EvidenceStatus.ANALYZED.value:          ("#10b981", "#0a3622"),
    EvidenceStatus.FAILED.value:            ("#f87171", "#4a1a1a"),
}

_COLUMNS = ["#", "Evidence №", "Filename", "Status", "SHA-256 (partial)", "Size", "Imported UTC"]


def _format_size(n: Optional[int]) -> str:
    if n is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class EvidenceTable(QWidget):
    """
    Evidence list table widget.
    Double-click a row to emit evidence_selected(evidence_id).
    """
    evidence_selected = Signal(str)  # evidence_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._evidence: list[EvidenceItem] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._empty_label = QLabel("No evidence imported for this case yet.")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._empty_label.setStyleSheet("color: #6b7280; font-size: 12px; padding: 24px;")
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
            "gridline-color: #1e3a5f; border: 1px solid #1e3a5f; border-radius: 6px; }"
            "QHeaderView::section { background: #0a1628; color: #7ec8e3; "
            "border-bottom: 1px solid #1e3a5f; padding: 6px; font-weight: bold; }"
            "QTableWidget::item:alternate { background: #0a1628; }"
            "QTableWidget::item:selected { background: #1e3a5f; }"
        )
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.setVisible(False)
        layout.addWidget(self._table)

    def load(self, evidence_items: list[EvidenceItem]) -> None:
        """Populate the table from a list of EvidenceItem ORM objects."""
        self._evidence = list(evidence_items)
        self._table.setRowCount(0)

        if not self._evidence:
            self._empty_label.setVisible(True)
            self._table.setVisible(False)
            return

        self._empty_label.setVisible(False)
        self._table.setVisible(True)

        for row_idx, ev in enumerate(self._evidence):
            self._table.insertRow(row_idx)

            # Row number
            self._set_cell(row_idx, 0, str(row_idx + 1), Qt.AlignCenter)
            # Evidence number
            self._set_cell(row_idx, 1, ev.evidence_number or "—")
            # Filename (truncated)
            self._set_cell(row_idx, 2, ev.sanitized_filename or ev.source_filename or "—")
            # Status with color
            status_val = ev.status or EvidenceStatus.IMPORTED.value
            status_item = QTableWidgetItem(status_val)
            status_item.setTextAlignment(Qt.AlignCenter)
            fg, bg = _STATUS_COLORS.get(status_val, ("#9aa5b4", "#1e2d3d"))
            status_item.setForeground(Qt.GlobalColor.white)
            from PySide6.QtGui import QColor
            status_item.setBackground(QColor(bg))
            status_item.setForeground(QColor(fg))
            self._table.setItem(row_idx, 3, status_item)
            # SHA-256 truncated
            sha = ev.original_sha256 or "—"
            self._set_cell(row_idx, 4, sha[:16] + "…" if len(sha) > 16 else sha)
            # File size
            self._set_cell(row_idx, 5, _format_size(ev.file_size_bytes), Qt.AlignRight | Qt.AlignVCenter)
            # Imported at
            imported = "—"
            if ev.imported_at_utc:
                imported = ev.imported_at_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
            self._set_cell(row_idx, 6, imported)

        self._table.resizeColumnsToContents()

    def _set_cell(self, row: int, col: int, text: str, align: Qt.AlignmentFlag = Qt.AlignLeft | Qt.AlignVCenter) -> None:
        item = QTableWidgetItem(text)
        item.setTextAlignment(align)
        self._table.setItem(row, col, item)

    def _on_double_click(self, index) -> None:
        row = index.row()
        if 0 <= row < len(self._evidence):
            self.evidence_selected.emit(self._evidence[row].id)
