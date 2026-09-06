"""
forensiq/ui/pages/adapter_capabilities_page.py
------------------------------------------------
Vendor Stream Adapters & Carving Recovery Engine UI.

Displays:
  - Multi-vendor capability matrix (Dahua, Hikvision, TP-Link, Generic, Fallback)
  - Working copy header inspection & vendor signature detection
  - Stream hex dump viewer (first 512 bytes)
  - Annex-B NAL unit video carving and stream reconstruction
  - Carved derivative file manager and audit records

Phase 7: Fully implemented.
"""

import binascii
import json
import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.adapters.base import BaseAdapter
from forensiq.adapters.registry import get_registry
from forensiq.constants import RecoveryStatus
from forensiq.database import get_session, session_scope
from forensiq.models.device import AdapterProfile
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.recovery import RecoveryResult
from forensiq.services.adapter_service import get_working_copy_path
from forensiq.services.recovery_service import (
    MANDATORY_RECOVERY_WARNING,
    carve_video_stream,
    list_recovery_results_for_evidence,
    scan_annex_b_nalus,
)

logger = logging.getLogger(__name__)


def _format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format raw bytes into standard forensic hex dump with ASCII sidebar."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Pad hex part if last chunk is short
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


class CarvingWorker(QThread):
    """Background worker for video carving to prevent UI thread freezing."""

    finished = Signal(object, object)  # (RecoveryResult, Path)
    error = Signal(str)

    def __init__(self, evidence_id: str, actor_id: str, parent=None):
        super().__init__(parent)
        self._evidence_id = evidence_id
        self._actor_id = actor_id

    def run(self):
        try:
            with session_scope() as session:
                rec_res, path = carve_video_stream(
                    session=session,
                    evidence_id=self._evidence_id,
                    actor_id=self._actor_id,
                )
                self.finished.emit(rec_res, path)
        except Exception as exc:
            logger.exception("Carving worker error: %s", exc)
            self.error.emit(str(exc))


class AdapterCapabilitiesPage(QWidget):
    """Vendor Stream Adapters & Carving Recovery Engine Page."""

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._worker: Optional[CarvingWorker] = None
        self._evidence_items: list[EvidenceItem] = []

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # Header
        header = QWidget()
        h_layout = QVBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(4)

        title = QLabel("Vendor Stream Adapters & Carving Recovery Engine")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #38bdf8;")
        h_layout.addWidget(title)

        subtitle = QLabel(
            "Multi-Vendor DVR/NVR stream decoding (Dahua, Hikvision, TP-Link, ONVIF) "
            "and Annex-B NAL unit stream carving for damaged or unfinalized surveillance footage."
        )
        subtitle.setStyleSheet("color: #9aa5b4; font-size: 12px;")
        h_layout.addWidget(subtitle)
        main_layout.addWidget(header)

        # Scroll area for multi-section content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget()
        c_layout = QVBoxLayout(content)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(20)

        # Section 1: Capability Matrix
        c_layout.addWidget(self._build_capability_matrix_section())

        # Section 2: Stream Header Inspector & Vendor Detector
        c_layout.addWidget(self._build_header_inspector_section())

        # Section 3: Carving & Stream Reconstruction Engine
        c_layout.addWidget(self._build_carving_section())

        c_layout.addStretch()
        scroll.setWidget(content)
        main_layout.addWidget(scroll)

    def _build_capability_matrix_section(self) -> QWidget:
        box = QFrame()
        box.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 6px; padding: 14px; }"
        )
        layout = QVBoxLayout(box)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        sec_title = QLabel("1. Registered Vendor Adapter Capability Matrix")
        sec_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #7ec8e3;")
        top_row.addWidget(sec_title)
        top_row.addStretch()

        sync_btn = QPushButton("🔄  Sync Database Profiles")
        sync_btn.setFixedHeight(30)
        sync_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 0 12px; font-size: 11px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        sync_btn.clicked.connect(self._sync_profiles)
        top_row.addWidget(sync_btn)
        layout.addLayout(top_row)

        self._adapter_table = QTableWidget(0, 6)
        self._adapter_table.setHorizontalHeaderLabels([
            "Vendor / Profile",
            "Adapter ID",
            "Version",
            "Status",
            "Supported Containers",
            "Header Signatures",
        ])
        self._adapter_table.horizontalHeader().setStretchLastSection(True)
        self._adapter_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._adapter_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._adapter_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._adapter_table.setFixedHeight(180)
        self._adapter_table.setStyleSheet(
            "QTableWidget { background: #121f2d; color: #e8f0fe; border: 1px solid #1e3a5f; "
            "gridline-color: #1e3a5f; font-size: 12px; }"
            "QHeaderView::section { background: #0a1628; color: #38bdf8; padding: 6px; font-weight: bold; }"
        )
        layout.addWidget(self._adapter_table)
        return box

    def _build_header_inspector_section(self) -> QWidget:
        box = QFrame()
        box.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 6px; padding: 14px; }"
        )
        layout = QVBoxLayout(box)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        sec_title = QLabel("2. Stream Header & Magic Signature Inspector")
        sec_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #7ec8e3;")
        top_row.addWidget(sec_title)
        top_row.addStretch()

        ev_lbl = QLabel("Exhibit:")
        ev_lbl.setStyleSheet("color: #9aa5b4; font-size: 12px; font-weight: bold;")
        top_row.addWidget(ev_lbl)

        self._evidence_combo = QComboBox()
        self._evidence_combo.setMinimumWidth(240)
        self._evidence_combo.setStyleSheet(
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px;"
        )
        self._evidence_combo.currentIndexChanged.connect(self._inspect_selected_stream)
        top_row.addWidget(self._evidence_combo)

        inspect_btn = QPushButton("🔍  Inspect Stream")
        inspect_btn.setFixedHeight(30)
        inspect_btn.setStyleSheet(
            "QPushButton { background: #164e63; color: #38bdf8; border: 1px solid #0891b2; "
            "border-radius: 4px; padding: 0 12px; font-weight: bold; font-size: 11px; }"
            "QPushButton:hover { background: #155e75; }"
        )
        inspect_btn.clicked.connect(self._inspect_selected_stream)
        top_row.addWidget(inspect_btn)
        layout.addLayout(top_row)

        # Status badge row
        info_row = QHBoxLayout()
        self._vendor_badge = QLabel("Detected Adapter: —")
        self._vendor_badge.setStyleSheet(
            "background: #1e2d3d; color: #9aa5b4; border: 1px solid #374151; "
            "padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;"
        )
        info_row.addWidget(self._vendor_badge)

        self._ml_badge = QLabel("ML Sector Classifier: —")
        self._ml_badge.setStyleSheet(
            "background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; "
            "padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;"
        )
        info_row.addWidget(self._ml_badge)

        self._basis_lbl = QLabel("Select an exhibit to inspect its working copy header.")
        self._basis_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        info_row.addWidget(self._basis_lbl)
        info_row.addStretch()
        layout.addLayout(info_row)

        # Hex Dump Text Box
        self._hex_view = QTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setFont(QFont("Courier New", 9))
        self._hex_view.setFixedHeight(160)
        self._hex_view.setStyleSheet(
            "background: #080f18; color: #a5f3fc; border: 1px solid #1e3a5f; "
            "border-radius: 4px; padding: 8px;"
        )
        self._hex_view.setPlaceholderText("Hex dump of working copy header (first 512 bytes) will appear here...")
        layout.addWidget(self._hex_view)

        return box

    def _build_carving_section(self) -> QWidget:
        box = QFrame()
        box.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 6px; padding: 14px; }"
        )
        layout = QVBoxLayout(box)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        sec_title = QLabel("3. Video Stream Carving & Frame Reconstruction")
        sec_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #7ec8e3;")
        top_row.addWidget(sec_title)
        top_row.addStretch()

        self._carve_btn = QPushButton("🛠  Attempt Stream Carving & Recovery")
        self._carve_btn.setFixedHeight(34)
        self._carve_btn.setStyleSheet(
            "QPushButton { background: #065f46; color: #34d399; border: 1px solid #059669; "
            "border-radius: 5px; padding: 0 16px; font-weight: bold; }"
            "QPushButton:hover { background: #047857; }"
        )
        self._carve_btn.clicked.connect(self._start_carving)
        top_row.addWidget(self._carve_btn)
        layout.addLayout(top_row)

        # Mandatory Statutory Warning
        warning_frame = QFrame()
        warning_frame.setStyleSheet(
            "background: #451a03; border-left: 4px solid #f59e0b; border-radius: 4px; padding: 10px;"
        )
        w_layout = QVBoxLayout(warning_frame)
        w_layout.setContentsMargins(8, 6, 8, 6)
        w_lbl = QLabel(f"⚠ <b>FORENSIC LIMITATION NOTICE:</b> {MANDATORY_RECOVERY_WARNING}")
        w_lbl.setWordWrap(True)
        w_lbl.setStyleSheet("color: #fde68a; font-size: 11px;")
        w_layout.addWidget(w_lbl)
        layout.addWidget(warning_frame)

        # Progress bar (hidden by default)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(12)
        self._progress.setStyleSheet(
            "QProgressBar { background: #12181f; border: 1px solid #2d4a6a; border-radius: 3px; }"
            "QProgressBar::chunk { background: #34d399; }"
        )
        self._progress.hide()
        layout.addWidget(self._progress)

        # Results card
        self._result_card = QFrame()
        self._result_card.setStyleSheet(
            "background: #121f2d; border: 1px solid #1e3a5f; border-radius: 5px; padding: 12px;"
        )
        rc_layout = QVBoxLayout(self._result_card)
        rc_layout.setSpacing(6)

        rc_title = QLabel("Carved Derivative Results:")
        rc_title.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 12px;")
        rc_layout.addWidget(rc_title)

        self._result_details_lbl = QLabel("No recovery executed on current exhibit.")
        self._result_details_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        rc_layout.addWidget(self._result_details_lbl)

        btn_row = QHBoxLayout()
        self._open_derivative_btn = QPushButton("📂  Open Carved Derivative")
        self._open_derivative_btn.setFixedHeight(28)
        self._open_derivative_btn.setEnabled(False)
        self._open_derivative_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 0 12px; font-size: 11px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        self._open_derivative_btn.clicked.connect(self._open_active_derivative)
        btn_row.addWidget(self._open_derivative_btn)
        btn_row.addStretch()
        rc_layout.addLayout(btn_row)

        layout.addWidget(self._result_card)

        # Recovery results history table
        hist_title = QLabel("Prior Recovery Results for This Exhibit:")
        hist_title.setStyleSheet("font-size: 12px; font-weight: bold; color: #9aa5b4; margin-top: 6px;")
        layout.addWidget(hist_title)

        self._recovery_table = QTableWidget(0, 5)
        self._recovery_table.setHorizontalHeaderLabels([
            "Timestamp UTC",
            "Method",
            "Status",
            "Duration",
            "SHA-256 Digest",
        ])
        self._recovery_table.horizontalHeader().setStretchLastSection(True)
        self._recovery_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._recovery_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._recovery_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._recovery_table.setFixedHeight(120)
        self._recovery_table.setStyleSheet(
            "QTableWidget { background: #121f2d; color: #e8f0fe; border: 1px solid #1e3a5f; "
            "gridline-color: #1e3a5f; font-size: 11px; }"
            "QHeaderView::section { background: #0a1628; color: #38bdf8; padding: 4px; font-weight: bold; }"
        )
        layout.addWidget(self._recovery_table)

        self._last_recovered_path: Optional[Path] = None
        return box

    def refresh(self) -> None:
        """Reload adapter matrix and update active case evidence items."""
        self._populate_adapter_table()
        self._populate_evidence_combo()

    def _populate_adapter_table(self) -> None:
        adapters = get_registry().list_adapters()
        self._adapter_table.setRowCount(len(adapters))

        for row, adapter in enumerate(adapters):
            caps = adapter.capabilities()
            cap_data = caps.data or {}
            vendor = cap_data.get("vendor_name", adapter.ADAPTER_ID)
            status_val = caps.status
            containers = ", ".join(cap_data.get("supported_containers", []))
            signatures = ", ".join(cap_data.get("signatures", [])) or "Standard / Heuristic"

            self._adapter_table.setItem(row, 0, QTableWidgetItem(vendor))
            self._adapter_table.setItem(row, 1, QTableWidgetItem(adapter.ADAPTER_ID))
            self._adapter_table.setItem(row, 2, QTableWidgetItem(adapter.ADAPTER_VERSION))

            status_item = QTableWidgetItem(status_val)
            if status_val == "SUPPORTED":
                status_item.setForeground(QColor("#34d399"))
            elif status_val == "EXPERIMENTAL":
                status_item.setForeground(QColor("#fbbf24"))
            else:
                status_item.setForeground(QColor("#94a3b8"))
            self._adapter_table.setItem(row, 3, status_item)

            self._adapter_table.setItem(row, 4, QTableWidgetItem(containers))
            self._adapter_table.setItem(row, 5, QTableWidgetItem(signatures))

    def _populate_evidence_combo(self) -> None:
        case_id = self._main_window.active_case_id
        self._evidence_combo.clear()

        if not case_id:
            self._evidence_combo.addItem("No active case open", None)
            self._evidence_combo.setEnabled(False)
            self._hex_view.clear()
            self._vendor_badge.setText("Detected Adapter: —")
            return

        self._evidence_combo.setEnabled(True)
        session = get_session()
        try:
            items = (
                session.query(EvidenceItem)
                .filter_by(case_id=case_id)
                .order_by(EvidenceItem.evidence_number.asc())
                .all()
            )
            self._evidence_items = items
            if not items:
                self._evidence_combo.addItem("No exhibits in case", None)
                self._hex_view.clear()
                self._vendor_badge.setText("Detected Adapter: —")
                return

            for item in items:
                self._evidence_combo.addItem(
                    f"{item.evidence_number} — {item.sanitized_filename or item.source_filename}",
                    item.id,
                )
        finally:
            session.close()

        # Trigger initial stream inspection
        self._inspect_selected_stream()

    def _inspect_selected_stream(self) -> None:
        evidence_id = self._evidence_combo.currentData()
        if not evidence_id:
            self._hex_view.clear()
            self._vendor_badge.setText("Detected Adapter: —")
            return

        session = get_session()
        try:
            wc_path = get_working_copy_path(session, evidence_id)
            if not wc_path or not wc_path.exists():
                self._hex_view.setPlainText("[Warning: Working copy file not found on disk.]")
                self._vendor_badge.setText("Working Copy Missing")
                self._vendor_badge.setStyleSheet(
                    "background: #4a1a1a; color: #f87171; border: 1px solid #dc2626; padding: 4px 12px; border-radius: 4px;"
                )
                return

            # Read first 512 bytes for hex dump
            with open(wc_path, "rb") as f:
                header_data = f.read(512)

            self._hex_view.setPlainText(_format_hex_dump(header_data))

            # ML Sector Classification
            from forensiq.ml import predict_sector_class
            ml_class, ml_conf = predict_sector_class(header_data)
            self._ml_badge.setText(f"🤖 ML Classifier: {ml_class} ({ml_conf*100:.1f}%)")
            self._ml_badge.setStyleSheet(
                "background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; "
                "padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;"
            )

            # Detect adapter
            adapter = get_registry().detect_adapter(wc_path)
            resp = adapter.identify(wc_path)

            badge_text = f"✔ {adapter.ADAPTER_ID} ({resp.confidence} Confidence)"
            self._vendor_badge.setText(badge_text)
            self._vendor_badge.setStyleSheet(
                "background: #064e3b; color: #34d399; border: 1px solid #059669; padding: 4px 12px; border-radius: 4px;"
            )
            self._basis_lbl.setText(f"Basis: {resp.basis}")

            # Refresh recovery history for this evidence
            self._populate_recovery_history(session, evidence_id)
        finally:
            session.close()

    def _populate_recovery_history(self, session, evidence_id: str) -> None:
        runs = list_recovery_results_for_evidence(session, evidence_id)
        self._recovery_table.setRowCount(len(runs))

        for row, r in enumerate(runs):
            dt_str = r.created_at_utc.strftime("%Y-%m-%d %H:%M:%S UTC") if r.created_at_utc else "—"
            dur_str = f"{r.recovered_duration_seconds:.2f}s" if r.recovered_duration_seconds else "—"
            sha_str = (r.sha256[:16] + "…") if r.sha256 else "None (Unrecoverable)"

            self._recovery_table.setItem(row, 0, QTableWidgetItem(dt_str))
            self._recovery_table.setItem(row, 1, QTableWidgetItem(r.method))

            stat_item = QTableWidgetItem(r.status)
            if r.status == RecoveryStatus.COMPLETE.value:
                stat_item.setForeground(QColor("#34d399"))
            elif r.status == RecoveryStatus.PARTIAL.value:
                stat_item.setForeground(QColor("#fbbf24"))
            else:
                stat_item.setForeground(QColor("#f87171"))
            self._recovery_table.setItem(row, 2, stat_item)

            self._recovery_table.setItem(row, 3, QTableWidgetItem(dur_str))
            self._recovery_table.setItem(row, 4, QTableWidgetItem(sha_str))

    def _sync_profiles(self) -> None:
        try:
            with session_scope() as session:
                profiles = get_registry().sync_adapter_profiles(session)
            QMessageBox.information(
                self,
                "Profiles Synchronized",
                f"Successfully synchronized {len(profiles)} adapter capability profiles with the database.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Sync Error", f"Failed to sync adapter profiles:\n{exc}")

    def _start_carving(self) -> None:
        evidence_id = self._evidence_combo.currentData()
        if not evidence_id:
            QMessageBox.warning(self, "No Exhibit", "Please select an evidence item to carve.")
            return

        self._carve_btn.setEnabled(False)
        self._progress.show()
        self._result_details_lbl.setText("Scanning working copy for Annex-B NAL unit headers and parameter sets...")

        self._worker = CarvingWorker(evidence_id, actor_id="Investigator", parent=self)
        self._worker.finished.connect(self._on_carving_finished)
        self._worker.error.connect(self._on_carving_error)
        self._worker.start()

    def _on_carving_finished(self, result: RecoveryResult, path: Optional[Path]) -> None:
        self._progress.hide()
        self._carve_btn.setEnabled(True)
        self._last_recovered_path = path

        if path and result.status in (RecoveryStatus.COMPLETE.value, RecoveryStatus.PARTIAL.value):
            self._open_derivative_btn.setEnabled(True)
            self._result_details_lbl.setText(
                f"✔ <b>Status:</b> {result.status} | <b>Confidence:</b> {result.confidence}<br>"
                f"<b>Derivative:</b> {path.name} ({path.stat().st_size / 1024:.1f} KB)<br>"
                f"<b>SHA-256:</b> <font color='#a5f3fc'>{result.sha256}</font><br>"
                f"<b>Duration:</b> ~{result.recovered_duration_seconds:.2f}s"
            )
            QMessageBox.information(
                self,
                "Stream Carving Complete",
                f"Stream carving successfully finished!\n\n"
                f"Status: {result.status}\n"
                f"Output: {path.name}\n"
                f"SHA-256: {result.sha256}\n\n"
                f"Derivative file saved in vault derivatives folder and recorded in chain of custody.",
            )
        else:
            self._open_derivative_btn.setEnabled(False)
            self._result_details_lbl.setText(
                "✖ <b>Status:</b> UNRECOVERABLE<br>"
                "No valid H.264/H.265 NAL unit headers were detected in this stream."
            )
            QMessageBox.warning(
                self,
                "Stream Unrecoverable",
                f"Carving concluded: The video stream could not be reconstructed.\n\n"
                f"{MANDATORY_RECOVERY_WARNING}",
            )

        # Refresh history table
        session = get_session()
        try:
            self._populate_recovery_history(session, self._evidence_combo.currentData())
        finally:
            session.close()

    def _on_carving_error(self, err_msg: str) -> None:
        self._progress.hide()
        self._carve_btn.setEnabled(True)
        self._result_details_lbl.setText(f"<font color='#f87171'>Carving Error: {err_msg}</font>")
        QMessageBox.critical(self, "Carving Error", f"Carving failed:\n{err_msg}")

    def _open_active_derivative(self) -> None:
        if self._last_recovered_path and self._last_recovered_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._last_recovered_path)))
