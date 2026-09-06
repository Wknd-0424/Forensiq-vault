"""
forensiq/ui/pages/custody_report_page.py
-----------------------------------------
Chain of Custody & Cryptographic Audit Ledger page.

Provides:
  - Cryptographic chain verification (SHA-256 link & payload validation)
  - Live status indicator: CHAIN INTACT / CHAIN COMPROMISED / EMPTY CHAIN
  - Mandatory forensic limitation notice
  - Ledger table with sequence, timestamp, action badge, actor, evidence, and hashes
  - Detailed Event Inspector with un-truncated hashes and canonical JSON viewer
  - "➕ Record Custody Event" dialog (for logging transfers, notes, disposition)
  - "Export JSON" and "Export CSV" audit ledger exports

Phase 3: Fully implemented.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.config import TOOL_VERSION
from forensiq.constants import ChainVerificationResult, CustodyAction
from forensiq.database import get_session, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.evidence import EvidenceItem
from forensiq.services.case_service import get_case
from forensiq.services.custody_service import (
    export_custody_ledger_csv,
    export_custody_ledger_json,
    get_chain_for_case,
    record_manual_event,
    verify_chain,
)
from forensiq.ui.widgets.warning_panel import ErrorPanel, WarningPanel
from forensiq.utils.canonical_json import canonical_dumps
from forensiq.utils.utc_utils import to_iso8601

# Color palette for action badges (fg, bg)
_ACTION_COLORS: dict[str, tuple[str, str]] = {
    CustodyAction.CASE_CREATED.value: ("#38bdf8", "#0c4a6e"),
    CustodyAction.EVIDENCE_IMPORTED.value: ("#22d3ee", "#164e63"),
    CustodyAction.HASH_CALCULATED.value: ("#fbbf24", "#451a03"),
    CustodyAction.ORIGINAL_PRESERVED.value: ("#c084fc", "#3b0764"),
    CustodyAction.READ_ONLY_SET.value: ("#34d399", "#064e3b"),
    CustodyAction.READ_ONLY_FAILED.value: ("#fb7185", "#4c0519"),
    CustodyAction.WORKING_COPY_CREATED.value: ("#818cf8", "#1e1b4b"),
    CustodyAction.WORKING_COPY_VERIFIED.value: ("#4ade80", "#14532d"),
    CustodyAction.WORKING_COPY_VERIFICATION_FAILED.value: ("#f87171", "#450a0a"),
    CustodyAction.CUSTODY_TRANSFERRED.value: ("#fb923c", "#431407"),
    CustodyAction.ANALYST_NOTE.value: ("#2dd4bf", "#134e4a"),
    CustodyAction.DISPOSITION_SET.value: ("#a78bfa", "#2e1065"),
    CustodyAction.REPORT_GENERATED.value: ("#60a5fa", "#1e3a8a"),
    CustodyAction.MANIFEST_GENERATED.value: ("#a3e635", "#1a2e05"),
}

_COLUMNS = [
    "#",
    "Timestamp UTC",
    "Action",
    "Actor / Officer",
    "Evidence Item",
    "Output SHA-256",
    "Previous Link",
    "Event Hash",
]


# ─────────────────────────────────────────────────────────────────────────────
# Manual Event Dialog
# ─────────────────────────────────────────────────────────────────────────────

class RecordCustodyDialog(QDialog):
    """Modal dialog allowing an investigator to append a verified event."""

    def __init__(self, case_id: str, default_actor: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Record Chain-of-Custody Event")
        self.setMinimumWidth(480)
        self.setStyleSheet("background: #0a1118; color: #e8f0fe;")

        self._case_id = case_id
        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(14)

        title = QLabel("➕ Record Official Custody Event")
        title.setStyleSheet("font-size: 15px; font-weight: bold; color: #7ec8e3;")
        self._layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight)

        field_style = (
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px;"
        )
        lbl_style = "color: #9aa5b4; font-size: 11px;"

        # Action combo
        self._action_combo = QComboBox()
        self._action_combo.setStyleSheet(field_style)
        manual_actions = [
            CustodyAction.CUSTODY_TRANSFERRED,
            CustodyAction.ANALYST_NOTE,
            CustodyAction.DISPOSITION_SET,
        ]
        for act in manual_actions:
            self._action_combo.addItem(act.value, act)
        form.addRow(QLabel("Custody Action:", styleSheet=lbl_style), self._action_combo)

        # Evidence item selection
        self._evidence_combo = QComboBox()
        self._evidence_combo.setStyleSheet(field_style)
        self._evidence_combo.addItem("(None / Case-wide)", None)
        self._populate_evidence_combo()
        form.addRow(QLabel("Related Evidence:", styleSheet=lbl_style), self._evidence_combo)

        # Actor / Officer
        self._actor_input = QLineEdit(default_actor)
        self._actor_input.setPlaceholderText("Investigator name or ID")
        self._actor_input.setStyleSheet(field_style)
        form.addRow(QLabel("Actor / Officer *:", styleSheet=lbl_style), self._actor_input)

        # Reason / Note
        self._reason_input = QTextEdit()
        self._reason_input.setPlaceholderText("Describe custody transfer destination, notes, or disposition details...")
        self._reason_input.setFixedHeight(80)
        self._reason_input.setStyleSheet(field_style)
        form.addRow(QLabel("Reason / Details *:", styleSheet=lbl_style), self._reason_input)

        self._layout.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #9aa5b4; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px 14px; }"
        )
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        save_btn = QPushButton("✔ Record Event")
        save_btn.setStyleSheet(
            "QPushButton { background: #1e5b8a; color: #e8f0fe; font-weight: bold; "
            "border: 1px solid #2d6a9f; border-radius: 4px; padding: 6px 16px; }"
            "QPushButton:hover { background: #2a7ab5; }"
        )
        save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(save_btn)

        self._layout.addLayout(btn_row)

    def _populate_evidence_combo(self) -> None:
        session = get_session()
        try:
            items = session.query(EvidenceItem).filter_by(case_id=self._case_id).all()
            for item in items:
                label = f"{item.evidence_number} ({item.sanitized_filename or item.source_filename})"
                self._evidence_combo.addItem(label, item.id)
        finally:
            session.close()

    def _on_save(self) -> None:
        actor = self._actor_input.text().strip()
        reason = self._reason_input.toPlainText().strip()
        if not actor:
            QMessageBox.warning(self, "Missing Field", "Please enter the Actor/Officer name.")
            return
        if not reason:
            QMessageBox.warning(self, "Missing Field", "Please enter a Reason/Note for this custody event.")
            return

        action = self._action_combo.currentData()
        evidence_id = self._evidence_combo.currentData()

        try:
            with session_scope() as session:
                record_manual_event(
                    session=session,
                    case_id=self._case_id,
                    action=action,
                    actor_id=actor,
                    evidence_id=evidence_id,
                    reason=reason,
                )
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error Recording Event", f"Could not record custody event:\n{e}")


class GenerateReportDialog(QDialog):
    """Modal dialog allowing an investigator to configure and generate court-admissible dossiers."""

    def __init__(self, case_id: str, default_actor: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Forensic Examination Dossier")
        self.setMinimumWidth(520)
        self.setStyleSheet("background: #0a1118; color: #e8f0fe;")

        self._case_id = case_id
        self.generated_path: Optional[Path] = None
        self.generated_sha256: Optional[str] = None
        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(14)

        title = QLabel("📜 Generate Forensic Report / Case Dossier")
        title.setStyleSheet("font-size: 15px; font-weight: bold; color: #34d399;")
        self._layout.addWidget(title)

        subtitle = QLabel(
            "Produces a standardized, court-admissible forensic dossier with embedded "
            "cryptographic chain of custody, stream sanity analysis, and Section 65B "
            "Indian Evidence Act / Section 63 BSA legal certification."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        self._layout.addWidget(subtitle)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight)

        field_style = (
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px;"
        )
        lbl_style = "color: #9aa5b4; font-size: 11px;"

        # Format combo
        self._format_combo = QComboBox()
        self._format_combo.setStyleSheet(field_style)
        self._format_combo.addItem("HTML — Interactive Court Dossier (with Print Styles)", "HTML")
        self._format_combo.addItem("PDF — Static Court-Admissible Document (A4)", "PDF")
        self._format_combo.addItem("JSON — Full Structured Dossier (Interchange Format)", "JSON")
        form.addRow(QLabel("Report Format *:", styleSheet=lbl_style), self._format_combo)

        # Actor / Examiner
        self._actor_input = QLineEdit(default_actor or "Investigator")
        self._actor_input.setStyleSheet(field_style)
        form.addRow(QLabel("Certifying Officer *:", styleSheet=lbl_style), self._actor_input)

        # Custom output location (optional)
        out_row = QHBoxLayout()
        self._output_input = QLineEdit()
        self._output_input.setPlaceholderText("(Default: Vault case reports directory)")
        self._output_input.setStyleSheet(field_style)
        out_row.addWidget(self._output_input)

        browse_btn = QPushButton("Browse…")
        browse_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px 12px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        browse_btn.clicked.connect(self._browse_output)
        out_row.addWidget(browse_btn)

        form.addRow(QLabel("Save Path (Optional):", styleSheet=lbl_style), out_row)
        self._layout.addLayout(form)

        # Legal notice box
        notice = QFrame()
        notice.setStyleSheet(
            "background: #0d2818; border: 1px solid #059669; border-radius: 5px; padding: 10px;"
        )
        n_layout = QVBoxLayout(notice)
        n_layout.setContentsMargins(10, 8, 10, 8)
        n_lbl = QLabel(
            "⚖ <b>Statutory Compliance:</b> Generating this report automatically binds "
            "the mathematical ledger state and appends a <code>REPORT_GENERATED</code> "
            "cryptographic event to the immutable chain of custody."
        )
        n_lbl.setWordWrap(True)
        n_lbl.setStyleSheet("color: #a7f3d0; font-size: 11px;")
        n_layout.addWidget(n_lbl)
        self._layout.addWidget(notice)

        # Button row
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #9aa5b4; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px 14px; }"
        )
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        gen_btn = QPushButton("✔ Generate & Hash Dossier")
        gen_btn.setStyleSheet(
            "QPushButton { background: #065f46; color: #34d399; font-weight: bold; "
            "border: 1px solid #059669; border-radius: 4px; padding: 6px 18px; }"
            "QPushButton:hover { background: #047857; }"
        )
        gen_btn.clicked.connect(self._on_generate)
        btn_row.addWidget(gen_btn)

        self._layout.addLayout(btn_row)

    def _browse_output(self) -> None:
        fmt = self._format_combo.currentData()
        ext_map = {"HTML": "HTML Files (*.html)", "PDF": "PDF Documents (*.pdf)", "JSON": "JSON Files (*.json)"}
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Output File",
            f"forensic_report.{fmt.lower()}",
            ext_map.get(fmt, "All Files (*.*)"),
        )
        if path:
            self._output_input.setText(path)

    def _on_generate(self) -> None:
        actor = self._actor_input.text().strip()
        if not actor:
            QMessageBox.warning(self, "Missing Field", "Please enter the certifying officer / investigator name.")
            return

        fmt = self._format_combo.currentData()
        out_path = self._output_input.text().strip() or None

        from forensiq.services.report_service import generate_forensic_report
        try:
            with session_scope() as session:
                report, target_path = generate_forensic_report(
                    session=session,
                    case_id=self._case_id,
                    report_format=fmt,
                    output_path=out_path,
                    actor_id=actor,
                )
                self.generated_path = target_path
                self.generated_sha256 = report.sha256
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Report Generation Error", f"Failed to generate forensic dossier:\n{exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Custody Report Page
# ─────────────────────────────────────────────────────────────────────────────

class CustodyReportPage(QWidget):
    """Full forensic Chain of Custody Ledger and Verification view."""

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._events: list[CustodyEvent] = []
        self._evidence_map: dict[str, str] = {}  # id -> evidence_number
        self._active_case_investigator: str = ""

        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # ── Page Header ────────────────────────────────────────────────────
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("⛓  Chain of Custody & Cryptographic Audit Ledger")
        title.setStyleSheet("color: #e8f0fe; font-size: 20px; font-weight: bold;")
        subtitle = QLabel("Append-only, SHA-256 hash-linked immutable forensic audit trail.")
        subtitle.setStyleSheet("color: #9aa5b4; font-size: 12px;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        # Stats chips
        self._blocks_count_lbl = QLabel("Events: 0")
        self._blocks_count_lbl.setStyleSheet(
            "background: #12181f; color: #7ec8e3; border: 1px solid #1e3a5f; "
            "padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 12px;"
        )
        header_layout.addWidget(self._blocks_count_lbl)

        root.addLayout(header_layout)

        # Mandatory forensic notice
        root.addWidget(WarningPanel(
            "TAMPER-EVIDENT AUDIT NOTICE — This custody ledger is tamper-evident within "
            "the application using SHA-256 hash chaining. Stronger protection requires "
            "protected backups, independently stored checkpoints, and strict "
            "organisation-level forensic chain-of-custody standard operating procedures."
        ))

        # No-case warning
        self._no_case_panel = ErrorPanel(
            "No case is currently open. Please create or open a case to view its custody ledger."
        )
        root.addWidget(self._no_case_panel)

        # ── Verification & Control Banner ──────────────────────────────────
        banner = QFrame()
        banner.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 8px; }"
        )
        banner_layout = QHBoxLayout(banner)
        banner_layout.setContentsMargins(16, 12, 16, 12)
        banner_layout.setSpacing(12)

        verify_box = QVBoxLayout()
        verify_row = QHBoxLayout()

        self._verify_btn = QPushButton("🔍  Verify Cryptographic Chain")
        self._verify_btn.setFixedHeight(34)
        self._verify_btn.setStyleSheet(
            "QPushButton { background: #1e5b8a; color: #e8f0fe; font-weight: bold; "
            "border: 1px solid #2d6a9f; border-radius: 5px; padding: 0 16px; font-size: 12px; }"
            "QPushButton:hover { background: #2a7ab5; }"
        )
        self._verify_btn.clicked.connect(self._verify_chain_action)
        verify_row.addWidget(self._verify_btn)

        self._status_badge = QLabel("UNVERIFIED")
        self._status_badge.setStyleSheet(
            "background: #1e2d3d; color: #9aa5b4; border: 1px solid #374151; "
            "padding: 4px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;"
        )
        verify_row.addWidget(self._status_badge)
        verify_row.addStretch()
        verify_box.addLayout(verify_row)

        self._verification_detail_lbl = QLabel("Click verify to validate sequential hash links.")
        self._verification_detail_lbl.setStyleSheet("color: #6b7280; font-size: 11px; margin-top: 2px;")
        verify_box.addWidget(self._verification_detail_lbl)
        banner_layout.addLayout(verify_box, stretch=3)

        # Right side action buttons
        actions_box = QHBoxLayout()
        self._generate_report_btn = QPushButton("📜  Generate Forensic Report")
        self._generate_report_btn.setFixedHeight(34)
        self._generate_report_btn.setStyleSheet(
            "QPushButton { background: #065f46; color: #34d399; border: 1px solid #059669; "
            "border-radius: 5px; padding: 0 14px; font-weight: bold; }"
            "QPushButton:hover { background: #047857; }"
        )
        self._generate_report_btn.clicked.connect(self._open_generate_report_dialog)
        actions_box.addWidget(self._generate_report_btn)

        self._record_btn = QPushButton("➕  Record Custody Event")
        self._record_btn.setFixedHeight(34)
        self._record_btn.setStyleSheet(
            "QPushButton { background: #164e63; color: #38bdf8; border: 1px solid #0891b2; "
            "border-radius: 5px; padding: 0 14px; font-weight: bold; }"
            "QPushButton:hover { background: #155e75; }"
        )
        self._record_btn.clicked.connect(self._open_record_dialog)
        actions_box.addWidget(self._record_btn)

        self._export_json_btn = QPushButton("⎘  Export JSON")
        self._export_json_btn.setFixedHeight(34)
        self._export_json_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 5px; padding: 0 12px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        self._export_json_btn.clicked.connect(self._export_json)
        actions_box.addWidget(self._export_json_btn)

        self._export_csv_btn = QPushButton("📄  Export CSV")
        self._export_csv_btn.setFixedHeight(34)
        self._export_csv_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 5px; padding: 0 12px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        self._export_csv_btn.clicked.connect(self._export_csv)
        actions_box.addWidget(self._export_csv_btn)

        banner_layout.addLayout(actions_box)
        root.addWidget(banner)

        # ── Filters Toolbar ────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet("color: #9aa5b4; font-weight: bold; font-size: 11px;")
        toolbar.addWidget(filter_lbl)

        combo_style = (
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px;"
        )

        self._evidence_filter = QComboBox()
        self._evidence_filter.setStyleSheet(combo_style)
        self._evidence_filter.addItem("All Evidence Items", None)
        self._evidence_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self._evidence_filter)

        self._action_filter = QComboBox()
        self._action_filter.setStyleSheet(combo_style)
        self._action_filter.addItem("All Actions", None)
        for action in CustodyAction:
            self._action_filter.addItem(action.value, action.value)
        self._action_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self._action_filter)

        toolbar.addStretch()
        root.addLayout(toolbar)

        # ── Splitter: Ledger Table | Event Detail Inspector ───────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle { background: #1e3a5f; }")

        # Table container
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)

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
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        table_layout.addWidget(self._table)
        splitter.addWidget(table_container)

        # Inspector container
        self._inspector = self._build_inspector()
        splitter.addWidget(self._inspector)

        splitter.setSizes([460, 240])
        root.addWidget(splitter, stretch=1)

    def _build_inspector(self) -> QWidget:
        panel = QFrame()
        panel.setStyleSheet(
            "QFrame { background: #0b1522; border: 1px solid #1e3a5f; border-radius: 6px; }"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(8)

        # Title bar
        title_row = QHBoxLayout()
        insp_title = QLabel("🔬 Event Cryptographic Inspector")
        insp_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 12px;")
        title_row.addWidget(insp_title)

        title_row.addStretch()
        copy_json_btn = QPushButton("⎘ Copy Event JSON")
        copy_json_btn.setStyleSheet(
            "QPushButton { background: #12181f; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 3px; padding: 3px 8px; font-size: 10px; }"
        )
        copy_json_btn.clicked.connect(self._copy_inspector_json)
        title_row.addWidget(copy_json_btn)
        layout.addLayout(title_row)

        # Content split: Info grid (left) | Raw Canonical JSON (right)
        body = QHBoxLayout()
        body.setSpacing(16)

        # Info column
        info_widget = QWidget()
        info_layout = QFormLayout(info_widget)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(4)
        info_layout.setLabelAlignment(Qt.AlignRight)

        mono_font = QFont("Courier New", 9)
        lbl_style = "color: #6b7280; font-size: 10px;"

        self._insp_id = QLabel("—")
        self._insp_id.setFont(mono_font)
        self._insp_id.setStyleSheet("color: #9aa5b4;")
        info_layout.addRow(QLabel("Event ID:", styleSheet=lbl_style), self._insp_id)

        self._insp_action = QLabel("—")
        self._insp_action.setStyleSheet("color: #e8f0fe; font-weight: bold;")
        info_layout.addRow(QLabel("Action:", styleSheet=lbl_style), self._insp_action)

        self._insp_prev_hash = QLabel("—")
        self._insp_prev_hash.setFont(mono_font)
        self._insp_prev_hash.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._insp_prev_hash.setStyleSheet("color: #f59e0b;")
        info_layout.addRow(QLabel("Previous Hash:", styleSheet=lbl_style), self._insp_prev_hash)

        self._insp_event_hash = QLabel("—")
        self._insp_event_hash.setFont(mono_font)
        self._insp_event_hash.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._insp_event_hash.setStyleSheet("color: #34d399; font-weight: bold;")
        info_layout.addRow(QLabel("Event Hash:", styleSheet=lbl_style), self._insp_event_hash)

        self._insp_reason = QLabel("—")
        self._insp_reason.setWordWrap(True)
        self._insp_reason.setStyleSheet("color: #cdd6e0;")
        info_layout.addRow(QLabel("Reason / Note:", styleSheet=lbl_style), self._insp_reason)

        body.addWidget(info_widget, stretch=3)

        # JSON preview column
        json_box = QVBoxLayout()
        json_box.setSpacing(2)
        json_lbl = QLabel("Canonical Hash Input Payload:")
        json_lbl.setStyleSheet("color: #6b7280; font-size: 10px;")
        json_box.addWidget(json_lbl)

        self._json_preview = QTextEdit()
        self._json_preview.setReadOnly(True)
        self._json_preview.setFont(QFont("Courier New", 9))
        self._json_preview.setStyleSheet(
            "background: #060b11; color: #a5f3fc; border: 1px solid #1e2d3d; border-radius: 4px;"
        )
        json_box.addWidget(self._json_preview)
        body.addLayout(json_box, stretch=4)

        layout.addLayout(body)
        return panel

    # ─────────────────────────────────────────────────────────────────────────
    # Page Lifecycle & Data Loading
    # ─────────────────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload the custody ledger for the active case."""
        case_id = self._main_window.active_case_id
        if not case_id:
            self._no_case_panel.setVisible(True)
            self._verify_btn.setEnabled(False)
            self._record_btn.setEnabled(False)
            self._export_json_btn.setEnabled(False)
            self._export_csv_btn.setEnabled(False)
            self._blocks_count_lbl.setText("Events: 0")
            self._events = []
            self._populate_table([])
            self._clear_inspector()
            self._set_status(ChainVerificationResult.EMPTY_CHAIN, ["No active case selected."])
            return

        self._no_case_panel.setVisible(False)
        self._verify_btn.setEnabled(True)
        self._record_btn.setEnabled(True)
        self._export_json_btn.setEnabled(True)
        self._export_csv_btn.setEnabled(True)

        session = get_session()
        try:
            case = get_case(session, case_id)
            self._active_case_investigator = case.created_by if case else ""

            # Load evidence map
            items = session.query(EvidenceItem).filter_by(case_id=case_id).all()
            self._evidence_map = {item.id: item.evidence_number for item in items}
            self._populate_evidence_filter(items)

            # Load events
            self._events = get_chain_for_case(session, case_id)
            self._blocks_count_lbl.setText(f"Events: {len(self._events)}")
        finally:
            session.close()

        self._apply_filters()
        # Automatically run verification upon viewing
        self._verify_chain_action()

    def _populate_evidence_filter(self, items: list[EvidenceItem]) -> None:
        current_data = self._evidence_filter.currentData()
        self._evidence_filter.blockSignals(True)
        self._evidence_filter.clear()
        self._evidence_filter.addItem("All Evidence Items", None)
        for item in items:
            label = f"{item.evidence_number} ({item.sanitized_filename or item.source_filename})"
            self._evidence_filter.addItem(label, item.id)

        idx = self._evidence_filter.findData(current_data)
        if idx >= 0:
            self._evidence_filter.setCurrentIndex(idx)
        self._evidence_filter.blockSignals(False)

    def _apply_filters(self) -> None:
        selected_evidence = self._evidence_filter.currentData()
        selected_action = self._action_filter.currentData()

        filtered = []
        for ev in self._events:
            if selected_evidence and ev.evidence_id != selected_evidence:
                continue
            if selected_action and ev.action != selected_action:
                continue
            filtered.append(ev)

        self._populate_table(filtered)

    def _populate_table(self, events: list[CustodyEvent]) -> None:
        self._table.setRowCount(0)
        mono_font = QFont("Courier New", 9)

        for row_idx, ev in enumerate(events):
            self._table.insertRow(row_idx)

            # 0: Seq
            self._set_cell(row_idx, 0, str(row_idx + 1), Qt.AlignCenter)

            # 1: Timestamp UTC
            ts = ev.action_timestamp_utc.strftime("%Y-%m-%d %H:%M:%S") if ev.action_timestamp_utc else "—"
            self._set_cell(row_idx, 1, ts, Qt.AlignCenter)

            # 2: Action badge
            action_val = ev.action or "UNKNOWN"
            action_item = QTableWidgetItem(action_val)
            action_item.setTextAlignment(Qt.AlignCenter)
            fg, bg = _ACTION_COLORS.get(action_val, ("#94a3b8", "#1e293b"))
            action_item.setBackground(QColor(bg))
            action_item.setForeground(QColor(fg))
            self._table.setItem(row_idx, 2, action_item)

            # 3: Actor / Officer
            self._set_cell(row_idx, 3, ev.actor_id or "—")

            # 4: Evidence item
            ev_num = self._evidence_map.get(ev.evidence_id, "Case-wide") if ev.evidence_id else "Case-wide"
            self._set_cell(row_idx, 4, ev_num)

            # 5: Output SHA-256 (partial)
            out_sha = ev.output_sha256 or ""
            out_txt = out_sha[:12] + "…" if len(out_sha) > 12 else out_sha or "—"
            item5 = self._set_cell(row_idx, 5, out_txt, Qt.AlignCenter)
            item5.setFont(mono_font)
            if out_sha:
                item5.setToolTip(f"Output SHA-256: {out_sha}")

            # 6: Previous Link (partial)
            prev = ev.previous_event_hash or ""
            prev_txt = prev[:12] + "…" if len(prev) > 12 else (prev if prev else "GENESIS")
            item6 = self._set_cell(row_idx, 6, prev_txt, Qt.AlignCenter)
            item6.setFont(mono_font)
            if prev:
                item6.setToolTip(f"Previous Block Hash: {prev}")

            # 7: Event Hash (partial)
            eh = ev.event_hash or ""
            eh_txt = eh[:12] + "…" if len(eh) > 12 else eh
            item7 = self._set_cell(row_idx, 7, eh_txt, Qt.AlignCenter)
            item7.setFont(mono_font)
            item7.setToolTip(f"Event Hash: {eh}")

            # Store the event object on the first cell for quick lookup
            self._table.item(row_idx, 0).setData(Qt.UserRole, ev)

        self._table.resizeColumnsToContents()
        if events:
            self._table.selectRow(0)
        else:
            self._clear_inspector()

    def _set_cell(self, row: int, col: int, text: str, align=Qt.AlignLeft | Qt.AlignVCenter) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setTextAlignment(align)
        self._table.setItem(row, col, item)
        return item

    # ─────────────────────────────────────────────────────────────────────────
    # Inspector
    # ─────────────────────────────────────────────────────────────────────────

    def _on_row_selected(self) -> None:
        selected_rows = self._table.selectedItems()
        if not selected_rows:
            self._clear_inspector()
            return

        row = self._table.currentRow()
        item = self._table.item(row, 0)
        if not item:
            return

        ev: CustodyEvent = item.data(Qt.UserRole)
        if not ev:
            return

        self._insp_id.setText(ev.id)
        self._insp_action.setText(ev.action)
        self._insp_prev_hash.setText(ev.previous_event_hash or "None (Genesis Block)")
        self._insp_event_hash.setText(ev.event_hash)
        self._insp_reason.setText(ev.reason or "No specific reason logged.")

        # Reconstruct canonical hash input
        hashable = {
            "id": ev.id,
            "case_id": ev.case_id,
            "evidence_id": ev.evidence_id,
            "actor_id": ev.actor_id,
            "action": ev.action,
            "action_timestamp_utc": to_iso8601(ev.action_timestamp_utc),
            "reason": ev.reason,
            "input_sha256": ev.input_sha256,
            "output_sha256": ev.output_sha256,
            "tool_version": ev.tool_version,
            "details_json": ev.details_json,
            "previous_event_hash": ev.previous_event_hash,
        }
        self._json_preview.setText(json.dumps(hashable, indent=2, sort_keys=True))

    def _clear_inspector(self) -> None:
        self._insp_id.setText("—")
        self._insp_action.setText("—")
        self._insp_prev_hash.setText("—")
        self._insp_event_hash.setText("—")
        self._insp_reason.setText("—")
        self._json_preview.clear()

    def _copy_inspector_json(self) -> None:
        text = self._json_preview.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self._verification_detail_lbl.setText("✔ Event JSON copied to clipboard.")

    # ─────────────────────────────────────────────────────────────────────────
    # Verification & Actions
    # ─────────────────────────────────────────────────────────────────────────

    def _verify_chain_action(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id:
            return

        session = get_session()
        try:
            result, errors = verify_chain(session, case_id)
        finally:
            session.close()

        self._set_status(result, errors)
        # Update global header badge
        self._main_window.update_chain_status(result.value)

    def _set_status(self, result: ChainVerificationResult, errors: list[str]) -> None:
        if result == ChainVerificationResult.VALID:
            self._status_badge.setText("✔  CHAIN INTACT")
            self._status_badge.setStyleSheet(
                "background: #1a4731; color: #34d399; border: 1px solid #059669; "
                "padding: 4px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;"
            )
            self._verification_detail_lbl.setText(
                f"Cryptographic verification passed — {len(self._events)} blocks verified against sequential SHA-256 hashes."
            )
            self._verification_detail_lbl.setStyleSheet("color: #34d399; font-size: 11px;")
        elif result == ChainVerificationResult.EMPTY_CHAIN:
            self._status_badge.setText("EMPTY CHAIN")
            self._status_badge.setStyleSheet(
                "background: #1e2d3d; color: #9aa5b4; border: 1px solid #374151; "
                "padding: 4px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;"
            )
            self._verification_detail_lbl.setText("No events recorded for this case.")
            self._verification_detail_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        else:
            self._status_badge.setText(f"✖  {result.value}")
            self._status_badge.setStyleSheet(
                "background: #4a1a1a; color: #f87171; border: 1px solid #dc2626; "
                "padding: 4px 14px; border-radius: 6px; font-weight: bold; font-size: 11px;"
            )
            err_msg = " | ".join(errors) if errors else "Chain integrity compromised."
            self._verification_detail_lbl.setText(f"⚠ TAMPER DETECTED: {err_msg}")
            self._verification_detail_lbl.setStyleSheet("color: #f87171; font-weight: bold; font-size: 11px;")

    def _open_record_dialog(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id:
            return

        dialog = RecordCustodyDialog(
            case_id=case_id,
            default_actor=self._active_case_investigator,
            parent=self,
        )
        if dialog.exec():
            self.refresh()

    def _open_generate_report_dialog(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id:
            QMessageBox.information(
                self, "No Active Case", "Please open or create a case before generating a report."
            )
            return

        dlg = GenerateReportDialog(
            case_id=case_id,
            default_actor=self._active_case_investigator,
            parent=self,
        )
        if dlg.exec() == QDialog.Accepted and dlg.generated_path:
            self.refresh()
            reply = QMessageBox.information(
                self,
                "Forensic Dossier Generated",
                f"Court-admissible forensic dossier successfully generated!\n\n"
                f"File: {dlg.generated_path.name}\n"
                f"Path: {dlg.generated_path}\n"
                f"SHA-256: {dlg.generated_sha256}\n\n"
                f"Chain of custody ledger updated with REPORT_GENERATED event.\n\n"
                f"Would you like to open the report now?",
                QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Ok,
                QMessageBox.StandardButton.Open,
            )
            if reply == QMessageBox.StandardButton.Open:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(dlg.generated_path)))

    def _export_json(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id:
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Custody Ledger (Canonical JSON)",
            f"custody_ledger_{case_id[:8]}.json",
            "JSON Files (*.json)",
        )
        if not path:
            return

        try:
            session = get_session()
            try:
                data = export_custody_ledger_json(session, case_id)
            finally:
                session.close()

            with open(path, "w", encoding="utf-8") as f:
                f.write(data)

            QMessageBox.information(
                self,
                "Export Complete",
                f"Custody ledger successfully exported to:\n{path}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export custody ledger:\n{e}")

    def _export_csv(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id:
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Custody Ledger (CSV)",
            f"custody_ledger_{case_id[:8]}.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return

        try:
            session = get_session()
            try:
                data = export_custody_ledger_csv(session, case_id)
            finally:
                session.close()

            with open(path, "w", encoding="utf-8") as f:
                f.write(data)

            QMessageBox.information(
                self,
                "Export Complete",
                f"Custody ledger CSV successfully exported to:\n{path}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not export custody ledger:\n{e}")
