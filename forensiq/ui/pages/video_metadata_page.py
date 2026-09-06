"""
forensiq/ui/pages/video_metadata_page.py
------------------------------------------
Video Stream & Container Metadata Analysis Page.

Features:
- Working copy analysis via vendor adapters and ffprobe.
- High-level metric summary cards (Container, Video, Audio, Adapter/Validation).
- Tab 1: Searchable and filterable Structured Metadata table (MetadataTable).
- Tab 2: Automated Forensic Validation Suite (Container/Codec, Timestamps, Duration/Bitrate, Dimensions).
- Tab 3: Monospace raw ffprobe JSON viewer with clipboard export.
- Background worker threads for analysis and validation to ensure responsive UI.
- Strict forensic compliance: only operates on verified working copies.

Phase 4: Fully implemented.
"""

import json
import logging
from typing import Any, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.database import get_session, session_scope
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.validation import ValidationRun
from forensiq.services.adapter_service import (
    analyze_evidence,
    detect_adapter_for_evidence,
    get_working_copy_path,
)
from forensiq.services.metadata_service import (
    get_metadata_for_evidence,
    is_ffprobe_available,
    parse_metadata,
    run_ffprobe,
)
from forensiq.services.validation_service import (
    ValidationStatus,
    get_latest_validation_run,
    run_validation,
)
from forensiq.ui.widgets.metadata_table import MetadataTable
from forensiq.ui.widgets.warning_panel import ErrorPanel, WarningPanel
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Background Workers
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisWorker(QThread):
    """Worker thread running adapter_service.analyze_evidence off the UI thread."""
    analysis_finished = Signal(bool, dict, list, str)  # success, data, records_list, error_msg

    def __init__(self, evidence_id: str, actor_id: str = "Investigator"):
        super().__init__()
        self._evidence_id = evidence_id
        self._actor_id = actor_id

    def run(self) -> None:
        try:
            with session_scope() as session:
                resp, records = analyze_evidence(
                    session=session,
                    evidence_id=self._evidence_id,
                    actor_id=self._actor_id,
                )
                data = resp.data or {}
                # Detach / serialize basic records summary for UI thread
                rec_dicts = [
                    {
                        "namespace": r.namespace,
                        "key": r.key,
                        "raw_value": r.raw_value,
                        "normalized_value": r.normalized_value,
                        "confidence": r.confidence,
                        "warning": r.warning,
                    }
                    for r in records
                ]
                err = resp.error or (" | ".join(resp.warnings) if resp.status == "FAILED" else "")
                self.analysis_finished.emit(resp.status != "FAILED", data, rec_dicts, err)
        except Exception as exc:
            logger.exception("AnalysisWorker failed on evidence %s", self._evidence_id)
            self.analysis_finished.emit(False, {}, [], str(exc))


class ValidationWorker(QThread):
    """Worker thread running validation_service.run_validation off the UI thread."""
    validation_finished = Signal(bool, str, list, str)  # success, overall_status, results_list, error_msg

    def __init__(self, evidence_id: str, parsed_metadata: dict[str, Any], actor_id: str = "Investigator"):
        super().__init__()
        self._evidence_id = evidence_id
        self._parsed_metadata = parsed_metadata
        self._actor_id = actor_id

    def run(self) -> None:
        try:
            with session_scope() as session:
                run_rec, results = run_validation(
                    session=session,
                    evidence_id=self._evidence_id,
                    parsed_metadata=self._parsed_metadata,
                    actor_id=self._actor_id,
                )
                self.validation_finished.emit(True, run_rec.status, results, "")
        except Exception as exc:
            logger.exception("ValidationWorker failed on evidence %s", self._evidence_id)
            self.validation_finished.emit(False, "FAILED", [], str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Main Page Widget
# ─────────────────────────────────────────────────────────────────────────────

class VideoMetadataPage(QWidget):
    """
    Video stream, container metadata, and forensic validation page.
    """

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._selected_evidence_id: Optional[str] = None
        self._cached_parsed_metadata: dict[str, Any] = {}
        self._analysis_worker: Optional[AnalysisWorker] = None
        self._validation_worker: Optional[ValidationWorker] = None

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Header
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(4)
        title_lbl = QLabel("Video & Stream Metadata Analysis")
        title_lbl.setObjectName("page_title")
        header_vbox.addWidget(title_lbl)

        subtitle_lbl = QLabel(
            "ffprobe stream parsing, vendor adapter detection, and automated forensic validation."
        )
        subtitle_lbl.setObjectName("page_subtitle")
        header_vbox.addWidget(subtitle_lbl)
        main_layout.addLayout(header_vbox)

        # 2. Forensic Notice
        notice = WarningPanel(
            "FORENSIC INVARIANT: All extraction and validation operations run strictly "
            "on the hash-verified Working Copy. Original vaulted evidence remains read-only and untouched."
        )
        main_layout.addWidget(notice)

        # ffprobe warning panel (only visible if ffprobe is missing)
        self._ffprobe_warn = ErrorPanel(
            "⚠️  ffprobe executable was not found on your system PATH. "
            "Install FFmpeg or configure FFPROBE_PATH to enable real-time container and stream extraction. "
            "The tool will safely utilize fallback adapters without crashing."
        )
        self._ffprobe_warn.setVisible(not is_ffprobe_available())
        main_layout.addWidget(self._ffprobe_warn)

        # 3. Control & Selector Bar
        control_card = QFrame()
        control_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 6px; }"
        )
        control_layout = QHBoxLayout(control_card)
        control_layout.setContentsMargins(12, 10, 12, 10)
        control_layout.setSpacing(12)

        sel_lbl = QLabel("Select Evidence:")
        sel_lbl.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 12px;")
        control_layout.addWidget(sel_lbl)

        self._evidence_combo = QComboBox()
        self._evidence_combo.setMinimumWidth(320)
        self._evidence_combo.setStyleSheet(
            "QComboBox { background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px 12px; font-size: 12px; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox QAbstractItemView { background: #0d1821; color: #e8f0fe; selection-background-color: #1e3a5f; }"
        )
        self._evidence_combo.currentIndexChanged.connect(self._on_evidence_selected)
        control_layout.addWidget(self._evidence_combo)

        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.setStyleSheet(
            "QPushButton { background: #1a2332; color: #9aa5b4; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 6px 12px; font-size: 12px; }"
            "QPushButton:hover { background: #223046; color: #e8f0fe; }"
        )
        refresh_btn.clicked.connect(self.refresh)
        control_layout.addWidget(refresh_btn)

        control_layout.addStretch()

        self._analyze_btn = QPushButton("🔍 Analyze Working Copy")
        self._analyze_btn.setStyleSheet(
            "QPushButton { background: #0284c7; color: #ffffff; font-weight: bold; "
            "border-radius: 4px; padding: 7px 16px; font-size: 12px; }"
            "QPushButton:hover { background: #0369a1; }"
            "QPushButton:disabled { background: #1e2d3d; color: #64748b; }"
        )
        self._analyze_btn.clicked.connect(self._start_analysis)
        control_layout.addWidget(self._analyze_btn)

        self._validate_btn = QPushButton("🛡 Run Forensic Validation")
        self._validate_btn.setStyleSheet(
            "QPushButton { background: #059669; color: #ffffff; font-weight: bold; "
            "border-radius: 4px; padding: 7px 16px; font-size: 12px; }"
            "QPushButton:hover { background: #047857; }"
            "QPushButton:disabled { background: #1e2d3d; color: #64748b; }"
        )
        self._validate_btn.clicked.connect(self._start_validation)
        control_layout.addWidget(self._validate_btn)

        main_layout.addWidget(control_card)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # indeterminate
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(
            "QProgressBar { background: #12181f; border-radius: 3px; border: none; }"
            "QProgressBar::chunk { background: #38bdf8; border-radius: 3px; }"
        )
        self._progress_bar.setVisible(False)
        main_layout.addWidget(self._progress_bar)

        # Status Label
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px; margin-left: 4px;")
        main_layout.addWidget(self._status_lbl)

        # 4. Summary Metric Cards
        self._summary_frame = self._build_summary_cards()
        main_layout.addWidget(self._summary_frame)

        # 5. Deep-Dive Tabs
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #1e3a5f; background: #0a1118; border-radius: 6px; }"
            "QTabBar::tab { background: #0d1821; color: #9aa5b4; padding: 8px 18px; "
            "border: 1px solid #1e3a5f; border-bottom: none; border-top-left-radius: 4px; "
            "border-top-right-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 4px; }"
            "QTabBar::tab:selected { background: #122132; color: #38bdf8; border-bottom: 2px solid #38bdf8; }"
            "QTabBar::tab:hover:!selected { background: #152233; color: #e8f0fe; }"
        )

        # Tab 1: Structured Metadata
        self._metadata_table = MetadataTable(self)
        self._tabs.addTab(self._metadata_table, "Structured Metadata")

        # Tab 2: Forensic Validation Suite
        self._validation_widget = self._build_validation_tab()
        self._tabs.addTab(self._validation_widget, "Forensic Validation Suite")

        # Tab 3: Raw ffprobe JSON
        self._raw_json_widget = self._build_raw_json_tab()
        self._tabs.addTab(self._raw_json_widget, "Raw ffprobe JSON")

        main_layout.addWidget(self._tabs, stretch=1)

    # ─────────────────────────────────────────────────────────────────────────
    # Summary Cards
    # ─────────────────────────────────────────────────────────────────────────

    def _build_summary_cards(self) -> QWidget:
        container = QWidget()
        layout = QGridLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Card 1: Container
        card1, self._c_fmt, self._c_dur, self._c_size, self._c_br = self._create_card(
            "📦 CONTAINER FORMAT",
            [("Format:", "—"), ("Duration:", "—"), ("File Size:", "—"), ("Bitrate:", "—")],
        )
        layout.addWidget(card1, 0, 0)

        # Card 2: Video Stream
        card2, self._v_codec, self._v_res, self._v_fps, self._v_pix = self._create_card(
            "🎬 VIDEO STREAM",
            [("Codec:", "—"), ("Resolution:", "—"), ("Frame Rate:", "—"), ("Pixel Format:", "—")],
        )
        layout.addWidget(card2, 0, 1)

        # Card 3: Audio Stream
        card3, self._a_codec, self._a_ch, self._a_rate, self._a_br = self._create_card(
            "🔊 AUDIO STREAM",
            [("Codec:", "—"), ("Channels:", "—"), ("Sample Rate:", "—"), ("Bitrate:", "—")],
        )
        layout.addWidget(card3, 0, 2)

        # Card 4: Adapter & Validation
        card4, self._ad_id, self._val_status, self._val_time, self._ad_cap = self._create_card(
            "🛡 ADAPTER & INTEGRITY",
            [("Adapter:", "—"), ("Validation:", "NOT RUN"), ("Last Check:", "—"), ("Working Copy:", "—")],
        )
        layout.addWidget(card4, 0, 3)

        return container

    def _create_card(self, title: str, fields: list[tuple[str, str]]) -> tuple[QFrame, ...]:
        card = QFrame()
        card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 8px; }"
        )
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(10, 8, 10, 8)
        vbox.setSpacing(6)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 11px; letter-spacing: 0.5px;")
        vbox.addWidget(title_lbl)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #1e3a5f; margin-bottom: 2px;")
        vbox.addWidget(sep)

        value_labels = []
        for label_text, default_val in fields:
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
            val = QLabel(default_val)
            val.setStyleSheet("color: #e8f0fe; font-size: 11px; font-weight: 600;")
            val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            row.addWidget(lbl)
            row.addWidget(val)
            vbox.addLayout(row)
            value_labels.append(val)

        return (card, *value_labels)

    # ─────────────────────────────────────────────────────────────────────────
    # Validation Tab
    # ─────────────────────────────────────────────────────────────────────────

    def _build_validation_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        # Top status banner
        self._val_banner = QFrame()
        self._val_banner.setStyleSheet(
            "QFrame { background: #12181f; border: 1px solid #2d4a6a; border-radius: 6px; padding: 8px; }"
        )
        b_layout = QHBoxLayout(self._val_banner)
        b_layout.setContentsMargins(12, 6, 12, 6)

        self._val_overall_badge = QLabel("NOT RUN")
        self._val_overall_badge.setStyleSheet(
            "background: #1e293b; color: #94a3b8; font-weight: bold; "
            "padding: 4px 10px; border-radius: 4px; font-size: 12px;"
        )
        b_layout.addWidget(self._val_overall_badge)

        self._val_summary_lbl = QLabel("No validation run recorded for this evidence item.")
        self._val_summary_lbl.setStyleSheet("color: #cdd6e0; font-size: 12px; margin-left: 8px;")
        b_layout.addWidget(self._val_summary_lbl, stretch=1)

        layout.addWidget(self._val_banner)

        # Scroll area for 4 checks
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        scroll_content = QWidget()
        self._checks_layout = QVBoxLayout(scroll_content)
        self._checks_layout.setContentsMargins(0, 4, 0, 4)
        self._checks_layout.setSpacing(10)

        self._check_widgets: list[QFrame] = []
        for check_name in [
            "1. Container & Codec Alignment",
            "2. Timestamp Sanity Check",
            "3. Duration & Bitrate Consistency",
            "4. Video Stream Dimensions & FPS",
        ]:
            card = self._create_check_card(check_name)
            self._check_widgets.append(card)
            self._checks_layout.addWidget(card)

        self._checks_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, stretch=1)

        return widget

    def _create_check_card(self, check_title: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 6px; padding: 10px; }"
        )
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(12, 8, 12, 8)
        vbox.setSpacing(6)

        top_row = QHBoxLayout()
        title = QLabel(check_title)
        title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 12px;")
        top_row.addWidget(title)

        badge = QLabel("PENDING")
        badge.setObjectName("badge")
        badge.setStyleSheet(
            "background: #1e293b; color: #94a3b8; font-weight: bold; "
            "padding: 2px 8px; border-radius: 4px; font-size: 11px;"
        )
        top_row.addWidget(badge)
        vbox.addLayout(top_row)

        msg = QLabel("Waiting for validation execution...")
        msg.setObjectName("msg")
        msg.setWordWrap(True)
        msg.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        vbox.addWidget(msg)

        return card

    def _update_check_card(self, card: QFrame, status: str, message: str) -> None:
        badge = card.findChild(QLabel, "badge")
        msg = card.findChild(QLabel, "msg")

        if badge:
            badge.setText(status)
            if status == ValidationStatus.PASSED:
                badge.setStyleSheet("background: #064e3b; color: #34d399; font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 11px;")
            elif status == ValidationStatus.WARNING:
                badge.setStyleSheet("background: #451a03; color: #fbbf24; font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 11px;")
            elif status == ValidationStatus.FAILED:
                badge.setStyleSheet("background: #450a0a; color: #f87171; font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 11px;")
            else:
                badge.setStyleSheet("background: #1e293b; color: #94a3b8; font-weight: bold; padding: 2px 8px; border-radius: 4px; font-size: 11px;")

        if msg:
            msg.setText(message)
            msg.setStyleSheet("color: #e8f0fe; font-size: 11px;")

    # ─────────────────────────────────────────────────────────────────────────
    # Raw JSON Tab
    # ─────────────────────────────────────────────────────────────────────────

    def _build_raw_json_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        info_lbl = QLabel("ffprobe stdout stream (Formatted JSON)")
        info_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        top_bar.addWidget(info_lbl)

        top_bar.addStretch()

        copy_btn = QPushButton("📋 Copy JSON")
        copy_btn.setStyleSheet(
            "QPushButton { background: #1a2332; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 12px; font-size: 11px; }"
            "QPushButton:hover { background: #223046; color: #ffffff; }"
        )
        copy_btn.clicked.connect(self._copy_raw_json)
        top_bar.addWidget(copy_btn)
        layout.addLayout(top_bar)

        self._raw_json_edit = QTextEdit()
        self._raw_json_edit.setReadOnly(True)
        self._raw_json_edit.setFont(QFont("Courier New", 9))
        self._raw_json_edit.setStyleSheet(
            "QTextEdit { background: #080e14; color: #a5f3fc; border: 1px solid #1e3a5f; "
            "border-radius: 4px; padding: 8px; }"
        )
        self._raw_json_edit.setPlaceholderText("No raw ffprobe output available.")
        layout.addWidget(self._raw_json_edit, stretch=1)

        return widget

    def _copy_raw_json(self) -> None:
        text = self._raw_json_edit.toPlainText().strip()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self._status_lbl.setText("✓ Raw ffprobe JSON copied to clipboard.")

    # ─────────────────────────────────────────────────────────────────────────
    # Page Refresh & Evidence Loading
    # ─────────────────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload active case and evidence list."""
        self._ffprobe_warn.setVisible(not is_ffprobe_available())
        active_case_id = self._main_window.active_case_id

        self._evidence_combo.blockSignals(True)
        self._evidence_combo.clear()

        if not active_case_id:
            self._evidence_combo.addItem("No active case selected", None)
            self._evidence_combo.setEnabled(False)
            self._analyze_btn.setEnabled(False)
            self._validate_btn.setEnabled(False)
            self._clear_views()
            self._status_lbl.setText("Select an active case in Case Management first.")
            self._evidence_combo.blockSignals(False)
            return

        session = get_session()
        try:
            items = (
                session.query(EvidenceItem)
                .filter_by(case_id=active_case_id)
                .order_by(EvidenceItem.imported_at_utc.asc())
                .all()
            )
            if not items:
                self._evidence_combo.addItem("No evidence items in this case", None)
                self._evidence_combo.setEnabled(False)
                self._analyze_btn.setEnabled(False)
                self._validate_btn.setEnabled(False)
                self._clear_views()
                self._status_lbl.setText("Import evidence files on the Evidence Import page.")
                return

            self._evidence_combo.setEnabled(True)
            self._analyze_btn.setEnabled(True)

            selected_idx = 0
            for idx, item in enumerate(items):
                size_mb = f"{item.file_size_bytes / (1024 * 1024):.1f} MB" if item.file_size_bytes else "0 B"
                label = f"[{item.evidence_number}] {item.source_filename} ({size_mb})"
                self._evidence_combo.addItem(label, item.id)

                if (
                    self._main_window.active_evidence_id
                    and item.id == self._main_window.active_evidence_id
                ):
                    selected_idx = idx

            self._evidence_combo.setCurrentIndex(selected_idx)
            self._on_evidence_selected(selected_idx)

        finally:
            session.close()
            self._evidence_combo.blockSignals(False)

    def _on_evidence_selected(self, index: int) -> None:
        ev_id = self._evidence_combo.currentData()
        if not ev_id:
            self._selected_evidence_id = None
            self._clear_views()
            return

        self._selected_evidence_id = ev_id
        self._main_window.set_active_evidence_id(ev_id)
        self._load_evidence_details(ev_id)

    def _clear_views(self) -> None:
        self._cached_parsed_metadata = {}
        self._c_fmt.setText("—")
        self._c_dur.setText("—")
        self._c_size.setText("—")
        self._c_br.setText("—")
        self._v_codec.setText("—")
        self._v_res.setText("—")
        self._v_fps.setText("—")
        self._v_pix.setText("—")
        self._a_codec.setText("—")
        self._a_ch.setText("—")
        self._a_rate.setText("—")
        self._a_br.setText("—")
        self._ad_id.setText("—")
        self._val_status.setText("NOT RUN")
        self._val_status.setStyleSheet("color: #94a3b8; font-weight: 600;")
        self._val_time.setText("—")
        self._ad_cap.setText("—")
        self._metadata_table.load_records([])
        self._raw_json_edit.clear()

        self._val_overall_badge.setText("NOT RUN")
        self._val_overall_badge.setStyleSheet("background: #1e293b; color: #94a3b8; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
        self._val_summary_lbl.setText("No validation run recorded for this evidence item.")
        for card in self._check_widgets:
            self._update_check_card(card, "PENDING", "Waiting for validation execution...")

    def _load_evidence_details(self, evidence_id: str) -> None:
        """Load stored metadata and previous validation results from the database."""
        session = get_session()
        try:
            item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
            if not item:
                return

            # Check working copy path
            wc_path = get_working_copy_path(session, evidence_id)
            if wc_path and wc_path.exists():
                self._ad_cap.setText("✓ Verified")
                self._ad_cap.setStyleSheet("color: #34d399; font-weight: 600;")
            else:
                self._ad_cap.setText("Missing on disk")
                self._ad_cap.setStyleSheet("color: #f87171; font-weight: 600;")

            # Detect adapter
            adapter = detect_adapter_for_evidence(session, evidence_id)
            self._ad_id.setText(f"{adapter.ADAPTER_ID} v{adapter.ADAPTER_VERSION}")

            # Load MetadataRecords
            records = get_metadata_for_evidence(session, evidence_id)
            self._metadata_table.load_records(records)

            # Populate cards from records if available
            rec_map = {f"{r.namespace}:{r.key}": r.normalized_value or r.raw_value for r in records}
            if rec_map:
                self._populate_cards_from_map(rec_map, item.file_size_bytes)
                self._validate_btn.setEnabled(True)
                self._status_lbl.setText(f"Loaded {len(records)} extracted metadata records from database.")
            else:
                self._status_lbl.setText("No metadata extracted yet. Click 'Analyze Working Copy' to run.")
                self._validate_btn.setEnabled(False)

            # Load latest ValidationRun
            val_run = get_latest_validation_run(session, evidence_id)
            if val_run:
                self._display_validation_run(val_run)
            else:
                self._val_overall_badge.setText("NOT RUN")
                self._val_overall_badge.setStyleSheet("background: #1e293b; color: #94a3b8; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
                self._val_summary_lbl.setText("No validation run recorded for this evidence item.")
                self._val_status.setText("NOT RUN")
                self._val_status.setStyleSheet("color: #94a3b8; font-weight: 600;")
                self._val_time.setText("—")

        finally:
            session.close()

    def _populate_cards_from_map(self, m: dict[str, str], size_bytes: Optional[int]) -> None:
        # Container
        self._c_fmt.setText(m.get("format:format_name", "—"))
        self._c_dur.setText(m.get("format:duration", "—"))
        if size_bytes:
            self._c_size.setText(f"{size_bytes / (1024 * 1024):.2f} MB")
        else:
            self._c_size.setText(m.get("format:size_bytes", "—"))
        br = m.get("format:bit_rate")
        self._c_br.setText(f"{int(br):,} bps" if br and br.isdigit() else (br or "—"))

        # Video
        self._v_codec.setText(m.get("video:0:codec_name", "None"))
        self._v_res.setText(m.get("video:0:resolution", "—"))
        self._v_fps.setText(f"{m.get('video:0:fps', '—')} fps" if m.get("video:0:fps") else "—")
        self._v_pix.setText(m.get("video:0:pix_fmt", "—"))

        # Audio
        self._a_codec.setText(m.get("audio:0:codec_name", "None / Silent"))
        self._a_ch.setText(m.get("audio:0:channels", "—"))
        self._a_rate.setText(m.get("audio:0:sample_rate", "—"))
        self._a_br.setText(m.get("audio:0:bit_rate", "—"))

    # ─────────────────────────────────────────────────────────────────────────
    # Analysis & Validation Trigger Handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _start_analysis(self) -> None:
        if not self._selected_evidence_id:
            QMessageBox.warning(self, "No Evidence Selected", "Please select an evidence item to analyze.")
            return

        self._analyze_btn.setEnabled(False)
        self._validate_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._status_lbl.setText("Analyzing working copy with adapter and ffprobe...")

        self._analysis_worker = AnalysisWorker(self._selected_evidence_id)
        self._analysis_worker.analysis_finished.connect(self._on_analysis_finished)
        self._analysis_worker.start()

    def _on_analysis_finished(
        self, success: bool, data: dict, records: list, error_msg: str
    ) -> None:
        self._progress_bar.setVisible(False)
        self._analyze_btn.setEnabled(True)

        if not success:
            self._status_lbl.setText(f"Analysis failed: {error_msg}")
            QMessageBox.critical(
                self,
                "Analysis Error",
                f"Metadata extraction encountered an error:\n\n{error_msg}\n\n"
                "Ensure that ffprobe is installed and that the working copy is accessible.",
            )
            return

        self._cached_parsed_metadata = data
        self._status_lbl.setText(f"✓ Analysis complete. Extracted {len(records)} metadata records.")

        # Display raw ffprobe json
        raw_probe = data.get("raw_ffprobe")
        if raw_probe:
            self._raw_json_edit.setPlainText(json.dumps(raw_probe, indent=2))

        # Refresh page state from DB
        self._load_evidence_details(self._selected_evidence_id)

        # Trigger automatic forensic validation run
        self._start_validation()

    def _start_validation(self) -> None:
        if not self._selected_evidence_id:
            return

        # Prepare parsed metadata
        if not self._cached_parsed_metadata:
            # Reconstruct minimal parsed_metadata from DB records
            session = get_session()
            try:
                records = get_metadata_for_evidence(session, self._selected_evidence_id)
                if not records:
                    QMessageBox.information(
                        self,
                        "Validation Notice",
                        "No metadata has been extracted yet. Please click 'Analyze Working Copy' first.",
                    )
                    return
                # Try to extract on-demand or construct minimal dictionary
                wc_path = get_working_copy_path(session, self._selected_evidence_id)
                if wc_path and wc_path.exists() and is_ffprobe_available():
                    raw = run_ffprobe(wc_path)
                    self._cached_parsed_metadata = parse_metadata(raw)
                else:
                    # Synthesize from metadata records
                    c_dict = {}
                    v_list = []
                    a_list = []
                    for r in records:
                        if r.namespace == "format":
                            c_dict[r.key] = r.normalized_value or r.raw_value
                        elif r.namespace.startswith("video:"):
                            v_dict = {"index": 0}
                            v_dict[r.key] = r.normalized_value or r.raw_value
                            if not v_list:
                                v_list.append(v_dict)
                            else:
                                v_list[0][r.key] = r.normalized_value or r.raw_value
                    if "duration" in c_dict:
                        try:
                            c_dict["duration_sec"] = float(c_dict["duration"])
                        except Exception:
                            pass
                    if "bit_rate" in c_dict:
                        try:
                            c_dict["bit_rate"] = int(c_dict["bit_rate"])
                        except Exception:
                            pass
                    self._cached_parsed_metadata = {
                        "container": c_dict,
                        "video_streams": v_list,
                        "audio_streams": a_list,
                    }
            except Exception as exc:
                logger.warning("Could not build metadata for validation: %s", exc)
            finally:
                session.close()

        self._validate_btn.setEnabled(False)
        self._status_lbl.setText("Running forensic validation checks...")

        self._validation_worker = ValidationWorker(
            self._selected_evidence_id, self._cached_parsed_metadata
        )
        self._validation_worker.validation_finished.connect(self._on_validation_finished)
        self._validation_worker.start()

    def _on_validation_finished(
        self, success: bool, overall_status: str, results: list, error_msg: str
    ) -> None:
        self._validate_btn.setEnabled(True)
        if not success:
            self._status_lbl.setText(f"Validation failed: {error_msg}")
            QMessageBox.warning(self, "Validation Warning", f"Forensic validation error: {error_msg}")
            return

        self._status_lbl.setText(f"✓ Forensic validation completed with status: {overall_status}")
        self._val_time.setText(to_iso8601(now_utc()))

        # Update Overall Badge
        self._val_status.setText(overall_status)
        if overall_status == ValidationStatus.PASSED:
            self._val_status.setStyleSheet("color: #34d399; font-weight: bold;")
            self._val_overall_badge.setText("PASSED")
            self._val_overall_badge.setStyleSheet("background: #064e3b; color: #34d399; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
            self._val_summary_lbl.setText("All automated forensic sanity checks passed with no detected anomalies.")
        elif overall_status == ValidationStatus.WARNING:
            self._val_status.setStyleSheet("color: #fbbf24; font-weight: bold;")
            self._val_overall_badge.setText("WARNING")
            self._val_overall_badge.setStyleSheet("background: #451a03; color: #fbbf24; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
            self._val_summary_lbl.setText("One or more non-critical forensic warnings detected (e.g. non-standard codecs or missing tags).")
        else:
            self._val_status.setStyleSheet("color: #f87171; font-weight: bold;")
            self._val_overall_badge.setText("FAILED")
            self._val_overall_badge.setStyleSheet("background: #450a0a; color: #f87171; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
            self._val_summary_lbl.setText("CRITICAL FORENSIC ANOMALY: Stream headers, timestamps, or duration failed sanity tests.")

        # Update individual check cards
        for idx, r in enumerate(results):
            if idx < len(self._check_widgets):
                self._update_check_card(self._check_widgets[idx], r["status"], r["message"])

    def _display_validation_run(self, run: ValidationRun) -> None:
        """Display a persisted ValidationRun object."""
        self._val_status.setText(run.status)
        if run.status == ValidationStatus.PASSED:
            self._val_status.setStyleSheet("color: #34d399; font-weight: bold;")
            self._val_overall_badge.setText("PASSED")
            self._val_overall_badge.setStyleSheet("background: #064e3b; color: #34d399; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
        elif run.status == ValidationStatus.WARNING:
            self._val_status.setStyleSheet("color: #fbbf24; font-weight: bold;")
            self._val_overall_badge.setText("WARNING")
            self._val_overall_badge.setStyleSheet("background: #451a03; color: #fbbf24; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")
        else:
            self._val_status.setStyleSheet("color: #f87171; font-weight: bold;")
            self._val_overall_badge.setText("FAILED")
            self._val_overall_badge.setStyleSheet("background: #450a0a; color: #f87171; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;")

        self._val_time.setText(to_iso8601(run.performed_at_utc))
        self._val_summary_lbl.setText(f"Validation executed by {run.performed_by} at {to_iso8601(run.performed_at_utc)}")

        if run.results_json:
            try:
                results = json.loads(run.results_json)
                for idx, r in enumerate(results):
                    if idx < len(self._check_widgets):
                        self._update_check_card(self._check_widgets[idx], r["status"], r["message"])
            except Exception:
                pass
