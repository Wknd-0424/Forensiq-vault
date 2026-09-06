"""
forensiq/ui/widgets/metadata_table.py
--------------------------------------
Searchable QTableWidget for structured metadata records.

Columns:
  Namespace | Property Key | Raw Value | Normalized Value | Confidence

Phase 4: Fully implemented.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from forensiq.models.metadata import MetadataRecord

_COLUMNS = ["Namespace", "Property Key", "Raw Value", "Normalized Value", "Confidence"]


class MetadataTable(QWidget):
    """Searchable table showing metadata key-value pairs."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[MetadataRecord] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Search / filter row
        search_row = QHBoxLayout()
        search_lbl = QLabel("Filter Properties:")
        search_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        search_row.addWidget(search_lbl)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search by key, codec, resolution, namespace...")
        self._search_input.setStyleSheet(
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px;"
        )
        self._search_input.textChanged.connect(self._apply_filter)
        search_row.addWidget(self._search_input, stretch=1)
        layout.addLayout(search_row)

        # Empty state label
        self._empty_label = QLabel("No metadata extracted yet. Run 'Analyze Working Copy' to extract stream headers.")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._empty_label.setStyleSheet("color: #6b7280; font-size: 12px; padding: 24px;")
        layout.addWidget(self._empty_label)

        # Table
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
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
        self._table.setVisible(False)
        layout.addWidget(self._table, stretch=1)

    def load_records(self, records: list[MetadataRecord]) -> None:
        """Populate the table from MetadataRecord ORM objects."""
        self._records = list(records)
        self._apply_filter()

    def _apply_filter(self) -> None:
        query = self._search_input.text().strip().lower()
        self._table.setRowCount(0)

        if not self._records:
            self._empty_label.setVisible(True)
            self._table.setVisible(False)
            return

        filtered = []
        for r in self._records:
            if not query:
                filtered.append(r)
            else:
                combined = f"{r.namespace} {r.key} {r.raw_value} {r.normalized_value or ''}".lower()
                if query in combined:
                    filtered.append(r)

        if not filtered:
            self._empty_label.setText(f"No properties matched filter '{query}'.")
            self._empty_label.setVisible(True)
            self._table.setVisible(False)
            return

        self._empty_label.setVisible(False)
        self._table.setVisible(True)

        mono_font = QFont("Courier New", 9)

        for row_idx, r in enumerate(filtered):
            self._table.insertRow(row_idx)

            # Namespace
            ns_item = self._set_cell(row_idx, 0, r.namespace)
            ns_item.setForeground(QColor("#7ec8e3"))

            # Key
            k_item = self._set_cell(row_idx, 1, r.key)
            k_item.setFont(QFont("Segoe UI", 9, QFont.Bold))

            # Raw Value
            raw_item = self._set_cell(row_idx, 2, r.raw_value or "—")
            raw_item.setFont(mono_font)
            raw_item.setForeground(QColor("#a5f3fc"))

            # Normalized Value
            norm_item = self._set_cell(row_idx, 3, r.normalized_value or r.raw_value or "—")

            # Confidence
            conf = r.confidence or "HIGH"
            conf_item = self._set_cell(row_idx, 4, conf, Qt.AlignCenter)
            conf_item.setForeground(QColor("#34d399" if conf == "HIGH" else "#fbbf24"))

        self._table.resizeColumnsToContents()

    def _set_cell(self, row: int, col: int, text: str, align=Qt.AlignLeft | Qt.AlignVCenter) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setTextAlignment(align)
        self._table.setItem(row, col, item)
        return item
