"""
forensiq/ui/pages/timeline_ai_page.py
--------------------------------------
Synchronized Timeline & AI Triage Page.

Features:
- Multi-camera chronological event correlation.
- Interactive visual timeline scrubber (TimelineWidget).
- Timestamp normalization with drift offset adjustment and custody logging.
- AI-assisted video triage and anomaly detection (Gemini / Local heuristic fallback).
- Human analyst confirmation/rejection workflow for AI detections.
- Automated footage gap and time reversal anomaly detection.
- Export of normalized case timeline to JSON and CSV.

Phase 5: Fully implemented.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QPoint, QRectF, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.constants import (
    AnalystStatus,
    NormalizationMethod,
    ReviewerStatus,
    TimelineEventType,
)
from forensiq.database import get_session, session_scope
from forensiq.models.detection import AIDetection
from forensiq.models.evidence import EvidenceItem
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.services.adapter_service import get_working_copy_path
from forensiq.services.ai_service import (
    is_gemini_available,
    is_yolo_available,
    list_detections_for_case,
    review_detection,
    run_ai_triage,
)
from forensiq.services.timeline_service import (
    apply_timestamp_normalization,
    create_or_update_segment_from_evidence,
    detect_timeline_gaps,
    export_timeline_csv,
    export_timeline_json,
    get_case_timeline,
    get_segments_for_case,
)
from forensiq.ui.widgets.timeline_widget import TimelineWidget
from forensiq.ui.widgets.warning_panel import ErrorPanel, WarningPanel
from forensiq.utils.utc_utils import to_iso8601

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Background Worker for AI Triage
# ─────────────────────────────────────────────────────────────────────────────

class AITriageWorker(QThread):
    """Runs AI triage off the main thread."""
    triage_finished = Signal(bool, int, str)  # success, count, error_msg

    def __init__(self, segment_id: str, actor_id: str = "Investigator"):
        super().__init__()
        self._segment_id = segment_id
        self._actor_id = actor_id

    def run(self) -> None:
        try:
            with session_scope() as session:
                detections = run_ai_triage(
                    session=session,
                    segment_id=self._segment_id,
                    actor_id=self._actor_id,
                )
                self.triage_finished.emit(True, len(detections), "")
        except Exception as exc:
            logger.exception("AI Triage worker failed on segment %s", self._segment_id)
            self.triage_finished.emit(False, 0, str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Main Timeline & AI Page
# ─────────────────────────────────────────────────────────────────────────────

class TimelineAIPage(QWidget):
    """
    Forensic timeline analysis, timestamp normalization, and AI triage page.
    """

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._selected_evidence_id: Optional[str] = None
        self._selected_segment_id: Optional[str] = None
        self._selected_detection_id: Optional[str] = None
        self._triage_worker: Optional[AITriageWorker] = None

        # Video playback & frame canvas state
        self._cap: Optional[Any] = None
        self._current_video_path: Optional[Path] = None
        self._current_fps: float = 25.0
        self._total_frames: int = 0
        self._duration_seconds: float = 0.0
        self._current_position: float = 0.0
        self._is_playing: bool = False
        self._last_rendered_pixmap: Optional[QPixmap] = None
        self._all_detections_map: dict[str, AIDetection] = {}

        self._play_timer = QTimer(self)
        self._play_timer.timeout.connect(self._on_play_tick)

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Header
        header_box = QVBoxLayout()
        header_box.setSpacing(4)
        title_lbl = QLabel("Timeline Analysis & AI-Assisted Triage")
        title_lbl.setObjectName("page_title")
        header_box.addWidget(title_lbl)

        sub_lbl = QLabel(
            "Chronological event correlation, timestamp drift normalization, "
            "and AI object/motion detection with human review."
        )
        sub_lbl.setObjectName("page_subtitle")
        header_box.addWidget(sub_lbl)
        main_layout.addLayout(header_box)

        # 2. Forensic Notice
        notice = WarningPanel(
            "FORENSIC INVARIANT: Raw timestamps are preserved verbatim. Normalized UTC timestamps "
            "are derived values. AI triage outputs are investigative aids; human analyst review is mandatory."
        )
        main_layout.addWidget(notice)

        # 3. Control & Normalization Toolbar
        ctrl_card = QFrame()
        ctrl_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 6px; }"
        )
        ctrl_layout = QHBoxLayout(ctrl_card)
        ctrl_layout.setContentsMargins(12, 8, 12, 8)
        ctrl_layout.setSpacing(12)

        # Evidence selector
        ev_lbl = QLabel("Evidence:")
        ev_lbl.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 11px;")
        ctrl_layout.addWidget(ev_lbl)

        self._evidence_combo = QComboBox()
        self._evidence_combo.setMinimumWidth(240)
        self._evidence_combo.setStyleSheet(
            "QComboBox { background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; }"
            "QComboBox QAbstractItemView { background: #0d1821; color: #e8f0fe; }"
        )
        self._evidence_combo.currentIndexChanged.connect(self._on_evidence_selected)
        ctrl_layout.addWidget(self._evidence_combo)

        # Offset sign
        self._sign_combo = QComboBox()
        self._sign_combo.addItems(["+ (Ahead / Fast)", "- (Behind / Lag)"])
        self._sign_combo.setFixedWidth(120)
        self._sign_combo.setStyleSheet(
            "QComboBox { background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 6px; font-size: 11px; }"
        )
        ctrl_layout.addWidget(self._sign_combo)

        # Offset spinbox (seconds)
        off_lbl = QLabel("Drift Offset (sec):")
        off_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        ctrl_layout.addWidget(off_lbl)

        self._offset_spin = QDoubleSpinBox()
        self._offset_spin.setRange(0.0, 86400.0)
        self._offset_spin.setDecimals(1)
        self._offset_spin.setValue(0.0)
        self._offset_spin.setFixedWidth(80)
        self._offset_spin.setStyleSheet(
            "QDoubleSpinBox { background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px; font-size: 11px; }"
        )
        ctrl_layout.addWidget(self._offset_spin)

        # Normalization method
        self._method_combo = QComboBox()
        self._method_combo.addItems([
            NormalizationMethod.ANALYST_OFFSET.value,
            NormalizationMethod.NTP_REFERENCE.value,
            NormalizationMethod.REFERENCE_EVENT.value,
            NormalizationMethod.MANUFACTURER_DRIFT.value,
        ])
        self._method_combo.setFixedWidth(160)
        self._method_combo.setStyleSheet(
            "QComboBox { background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 6px; font-size: 11px; }"
        )
        ctrl_layout.addWidget(self._method_combo)

        self._apply_norm_btn = QPushButton("Apply Offset")
        self._apply_norm_btn.setStyleSheet(
            "QPushButton { background: #0284c7; color: #ffffff; font-weight: bold; "
            "border-radius: 4px; padding: 5px 12px; font-size: 11px; }"
            "QPushButton:hover { background: #0369a1; }"
        )
        self._apply_norm_btn.clicked.connect(self._apply_normalization)
        ctrl_layout.addWidget(self._apply_norm_btn)

        ctrl_layout.addStretch()

        # AI Triage Button
        self._triage_btn = QPushButton("⚡ Run AI Triage")
        self._triage_btn.setStyleSheet(
            "QPushButton { background: #7c3aed; color: #ffffff; font-weight: bold; "
            "border-radius: 4px; padding: 5px 14px; font-size: 11px; }"
            "QPushButton:hover { background: #6d28d9; }"
            "QPushButton:disabled { background: #1e2d3d; color: #64748b; }"
        )
        self._triage_btn.clicked.connect(self._start_ai_triage)
        ctrl_layout.addWidget(self._triage_btn)

        # Export buttons
        export_btn = QPushButton("Export JSON")
        export_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 5px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        export_btn.clicked.connect(self._export_json)
        ctrl_layout.addWidget(export_btn)

        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 5px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        export_csv_btn.clicked.connect(self._export_csv)
        ctrl_layout.addWidget(export_csv_btn)

        main_layout.addWidget(ctrl_card)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setFixedHeight(5)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(
            "QProgressBar { background: #12181f; border-radius: 2px; border: none; }"
            "QProgressBar::chunk { background: #a855f7; border-radius: 2px; }"
        )
        self._progress_bar.setVisible(False)
        main_layout.addWidget(self._progress_bar)

        # 4. Interactive Timeline Scrubber
        self._timeline_widget = TimelineWidget(self)
        self._timeline_widget.position_changed.connect(self._on_scrubber_moved)
        self._timeline_widget.event_selected.connect(self._on_timeline_marker_clicked)
        main_layout.addWidget(self._timeline_widget)

        # 5. Splitter: Event Ledger (Left) and Detail Inspectors (Right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1e3a5f; width: 2px; }")

        # Left: Event Table
        left_widget = self._build_event_table_panel()
        splitter.addWidget(left_widget)

        # Right: Detail Cards (Video Preview + AI Detections + Audit)
        right_widget = self._build_right_inspector_panel()
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter, stretch=1)

    # ─────────────────────────────────────────────────────────────────────────
    # Event Table Panel (Left)
    # ─────────────────────────────────────────────────────────────────────────

    def _build_event_table_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)

        # Filter row
        filter_row = QHBoxLayout()
        f_lbl = QLabel("Filter Events:")
        f_lbl.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        filter_row.addWidget(f_lbl)

        self._type_filter = QComboBox()
        self._type_filter.addItems(["All Types", "METADATA", "AI_PRELIMINARY", "ANALYST_BOOKMARK", "MANUAL_ENTRY"])
        self._type_filter.setStyleSheet(
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px; font-size: 11px;"
        )
        self._type_filter.currentIndexChanged.connect(self._apply_event_filter)
        filter_row.addWidget(self._type_filter)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search timeline description...")
        self._search_input.setStyleSheet(
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px;"
        )
        self._search_input.textChanged.connect(self._apply_event_filter)
        filter_row.addWidget(self._search_input, stretch=1)
        layout.addLayout(filter_row)

        # Table
        cols = ["UTC Time", "Raw / Offset", "Type", "Status", "Description"]
        self._event_table = QTableWidget(0, len(cols))
        self._event_table.setHorizontalHeaderLabels(cols)
        self._event_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._event_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._event_table.verticalHeader().setVisible(False)
        self._event_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._event_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._event_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._event_table.setAlternatingRowColors(True)
        self._event_table.setStyleSheet(
            "QTableWidget { background: #0d1821; color: #cdd6e0; "
            "gridline-color: #1e3a5f; border: 1px solid #1e3a5f; border-radius: 6px; }"
            "QHeaderView::section { background: #0a1628; color: #7ec8e3; padding: 5px; font-weight: bold; }"
            "QTableWidget::item:selected { background: #1e3a5f; }"
        )
        self._event_table.itemSelectionChanged.connect(self._on_table_selection_changed)
        layout.addWidget(self._event_table, stretch=1)

        return widget

    # ─────────────────────────────────────────────────────────────────────────
    # Right Inspector Panel
    # ─────────────────────────────────────────────────────────────────────────

    def _build_right_inspector_panel(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(12)

        # 1. Preview / Scrubber Card
        prev_card = QFrame()
        prev_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 8px; }"
        )
        prev_vbox = QVBoxLayout(prev_card)
        prev_vbox.setContentsMargins(10, 8, 10, 8)
        prev_vbox.setSpacing(8)

        prev_top = QHBoxLayout()
        prev_title = QLabel("🎬 VIDEO WORKING COPY PREVIEW")
        prev_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 11px;")
        prev_top.addWidget(prev_title)

        prev_top.addStretch()
        self._channel_tag = QLabel("Channel: CH-01")
        self._channel_tag.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        prev_top.addWidget(self._channel_tag)
        prev_vbox.addLayout(prev_top)

        # Video screen canvas
        self._screen_box = QLabel()
        self._screen_box.setAlignment(Qt.AlignCenter)
        self._screen_box.setMinimumHeight(240)
        self._screen_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._screen_box.setStyleSheet(
            "background: #000000; color: #64748b; border: 1px solid #1e3a5f; "
            "border-radius: 6px; font-size: 11px;"
        )
        self._screen_box.setText("▶ Select an evidence item to load video preview")
        prev_vbox.addWidget(self._screen_box)

        # Transport & Control bar
        transport_bar = QHBoxLayout()
        transport_bar.setSpacing(6)

        self._play_btn = QPushButton("▶ Play")
        self._play_btn.setFixedWidth(75)
        self._play_btn.setStyleSheet(
            "QPushButton { background: #1b3a4b; color: #a5f3fc; border: 1px solid #2d6a8f; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #235269; color: #ffffff; }"
        )
        self._play_btn.clicked.connect(self._toggle_playback)
        transport_bar.addWidget(self._play_btn)

        self._step_back_btn = QPushButton("⏮ -1s")
        self._step_back_btn.setFixedWidth(55)
        self._step_back_btn.setStyleSheet(
            "QPushButton { background: #121d28; color: #9aa5b4; border: 1px solid #243b55; "
            "border-radius: 4px; padding: 4px 6px; font-size: 10px; }"
            "QPushButton:hover { background: #1e334a; color: #e8f0fe; }"
        )
        self._step_back_btn.clicked.connect(lambda: self._step_position(-1.0))
        transport_bar.addWidget(self._step_back_btn)

        self._step_fwd_btn = QPushButton("⏭ +1s")
        self._step_fwd_btn.setFixedWidth(55)
        self._step_fwd_btn.setStyleSheet(
            "QPushButton { background: #121d28; color: #9aa5b4; border: 1px solid #243b55; "
            "border-radius: 4px; padding: 4px 6px; font-size: 10px; }"
            "QPushButton:hover { background: #1e334a; color: #e8f0fe; }"
        )
        self._step_fwd_btn.clicked.connect(lambda: self._step_position(1.0))
        transport_bar.addWidget(self._step_fwd_btn)

        self._tc_label = QLabel("Position: 00:00:00.000 / 00:00:00.000")
        self._tc_label.setStyleSheet("color: #a5f3fc; font-family: 'Courier New'; font-size: 11px; font-weight: bold;")
        transport_bar.addWidget(self._tc_label, stretch=1)

        self._meta_badge = QLabel("—")
        self._meta_badge.setStyleSheet("color: #64748b; font-size: 10px;")
        transport_bar.addWidget(self._meta_badge)

        prev_vbox.addLayout(transport_bar)
        layout.addWidget(prev_card)

        # 2. AI Detections Inspector Card
        ai_card = QFrame()
        ai_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 8px; }"
        )
        ai_vbox = QVBoxLayout(ai_card)
        ai_vbox.setContentsMargins(10, 8, 10, 8)
        ai_vbox.setSpacing(6)

        ai_top = QHBoxLayout()
        ai_title = QLabel("🤖 AI TRIAGE DETECTIONS")
        ai_title.setStyleSheet("color: #c084fc; font-weight: bold; font-size: 11px;")
        ai_top.addWidget(ai_title)

        ai_top.addStretch()
        if is_yolo_available():
            engine_text = "● YOLOv8 Triage Mode"
        elif is_gemini_available():
            engine_text = "● Gemini AI"
        else:
            engine_text = "● Local ML Mode"
        self._ai_engine_lbl = QLabel(engine_text)
        self._ai_engine_lbl.setStyleSheet("color: #a855f7; font-size: 10px; font-weight: bold;")
        ai_top.addWidget(self._ai_engine_lbl)
        ai_vbox.addLayout(ai_top)

        # Detections table
        det_cols = ["Class", "Confidence", "Timecode", "Review Status"]
        self._det_table = QTableWidget(0, len(det_cols))
        self._det_table.setHorizontalHeaderLabels(det_cols)
        self._det_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._det_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._det_table.verticalHeader().setVisible(False)
        self._det_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._det_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._det_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._det_table.setStyleSheet(
            "QTableWidget { background: #0a1118; color: #cdd6e0; border: 1px solid #1e3a5f; }"
            "QHeaderView::section { background: #0a1628; color: #c084fc; padding: 4px; font-size: 10px; }"
        )
        self._det_table.itemSelectionChanged.connect(self._on_detection_selected)
        ai_vbox.addWidget(self._det_table)

        # Review action buttons
        rev_row = QHBoxLayout()
        self._confirm_btn = QPushButton("✓ Confirm Finding")
        self._confirm_btn.setStyleSheet(
            "QPushButton { background: #065f46; color: #34d399; font-weight: bold; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; }"
            "QPushButton:hover { background: #047857; }"
            "QPushButton:disabled { background: #121f2d; color: #475569; }"
        )
        self._confirm_btn.clicked.connect(lambda: self._review_current_detection(ReviewerStatus.CONFIRMED.value))
        rev_row.addWidget(self._confirm_btn)

        self._reject_btn = QPushButton("✕ Reject False Positive")
        self._reject_btn.setStyleSheet(
            "QPushButton { background: #7f1d1d; color: #f87171; font-weight: bold; "
            "border-radius: 4px; padding: 4px 8px; font-size: 11px; }"
            "QPushButton:hover { background: #991b1b; }"
            "QPushButton:disabled { background: #121f2d; color: #475569; }"
        )
        self._reject_btn.clicked.connect(lambda: self._review_current_detection(ReviewerStatus.REJECTED.value))
        rev_row.addWidget(self._reject_btn)
        ai_vbox.addLayout(rev_row)

        layout.addWidget(ai_card, stretch=1)

        # 3. Gap & Normalization Summary Card
        audit_card = QFrame()
        audit_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; "
            "border-radius: 8px; padding: 8px; }"
        )
        audit_vbox = QVBoxLayout(audit_card)
        audit_vbox.setContentsMargins(10, 8, 10, 8)
        audit_vbox.setSpacing(4)

        audit_title = QLabel("⏱ CHRONOLOGY & GAP AUDIT")
        audit_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 11px;")
        audit_vbox.addWidget(audit_title)

        self._audit_msg = QLabel("No anomalies or temporal gaps detected in sequence.")
        self._audit_msg.setWordWrap(True)
        self._audit_msg.setStyleSheet("color: #9aa5b4; font-size: 11px;")
        audit_vbox.addWidget(self._audit_msg)

        layout.addWidget(audit_card)

        return container

    # ─────────────────────────────────────────────────────────────────────────
    # Page Refresh & Loading
    # ─────────────────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Reload active case, evidence list, timeline events, and detections."""
        active_case_id = self._main_window.active_case_id

        self._evidence_combo.blockSignals(True)
        self._evidence_combo.clear()

        if not active_case_id:
            self._evidence_combo.addItem("No active case", None)
            self._evidence_combo.setEnabled(False)
            self._apply_norm_btn.setEnabled(False)
            self._triage_btn.setEnabled(False)
            self._clear_views()
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
                self._evidence_combo.addItem("No evidence in case", None)
                self._evidence_combo.setEnabled(False)
                self._apply_norm_btn.setEnabled(False)
                self._triage_btn.setEnabled(False)
                self._clear_views()
                return

            self._evidence_combo.setEnabled(True)
            self._apply_norm_btn.setEnabled(True)
            self._triage_btn.setEnabled(True)

            if is_yolo_available():
                self._ai_engine_lbl.setText("● YOLOv8 Triage Mode")
            elif is_gemini_available():
                self._ai_engine_lbl.setText("● Gemini AI")
            else:
                self._ai_engine_lbl.setText("● Local ML Mode")

            selected_idx = 0
            for idx, item in enumerate(items):
                label = f"[{item.evidence_number}] {item.source_filename}"
                self._evidence_combo.addItem(label, item.id)
                if self._main_window.active_evidence_id and item.id == self._main_window.active_evidence_id:
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
        self._load_timeline_data(ev_id)

    def _clear_views(self) -> None:
        self._stop_playback()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None
        self._current_video_path = None
        self._last_rendered_pixmap = None
        self._all_detections_map.clear()
        self._event_table.setRowCount(0)
        self._det_table.setRowCount(0)
        self._timeline_widget.set_events([], 60.0)
        self._tc_label.setText("Position: 00:00:00.000 / 00:00:00.000")
        if hasattr(self, "_meta_badge"):
            self._meta_badge.setText("—")
        self._screen_box.clear()
        self._screen_box.setText("No video or evidence selected.")
        self._confirm_btn.setEnabled(False)
        self._reject_btn.setEnabled(False)

    def _load_timeline_data(self, evidence_id: str) -> None:
        session = get_session()
        try:
            active_case_id = self._main_window.active_case_id
            if not active_case_id:
                return

            # Ensure primary VideoSegment exists
            segment = create_or_update_segment_from_evidence(session, evidence_id)
            self._selected_segment_id = segment.id

            # Update preview card
            dur = segment.duration_seconds or 0.0
            mins = int(dur // 60)
            secs = dur % 60
            self._tc_label.setText(f"Position: 00:00:00.000 / {mins:02d}:{secs:06.3f}")
            self._channel_tag.setText(f"Channel: {segment.channel_id or 'CH-01'}")

            wc_path = get_working_copy_path(session, evidence_id)
            if wc_path and wc_path.exists():
                self._open_video_for_evidence(wc_path, segment)
            else:
                self._stop_playback()
                self._screen_box.clear()
                self._screen_box.setText("Working copy not present on disk.")

            # Load timeline events
            events = get_case_timeline(session, active_case_id)
            self._timeline_widget.set_events(events, dur if dur > 0 else 60.0)
            self._populate_event_table(events)

            # Load AI detections
            detections = list_detections_for_case(session, active_case_id)
            self._populate_detection_table(detections)

            # Run gap analysis
            gaps = detect_timeline_gaps(events)
            if gaps:
                self._audit_msg.setText(f"⚠️ {len(gaps)} temporal gap/discontinuity anomalies detected in sequence.")
                self._audit_msg.setStyleSheet("color: #fbbf24; font-size: 11px;")
            else:
                self._audit_msg.setText("✓ Chronological sequence is continuous. No temporal gaps detected.")
                self._audit_msg.setStyleSheet("color: #34d399; font-size: 11px;")

        finally:
            session.close()

    def _populate_event_table(self, events: list[TimelineEvent]) -> None:
        self._all_events = events
        self._apply_event_filter()

    def _apply_event_filter(self) -> None:
        if not hasattr(self, "_all_events"):
            return

        type_filter = self._type_filter.currentText()
        query = self._search_input.text().strip().lower()

        filtered = []
        for ev in self._all_events:
            if type_filter != "All Types" and ev.event_type != type_filter:
                continue
            if query and query not in (ev.description or "").lower():
                continue
            filtered.append(ev)

        self._event_table.setRowCount(0)
        mono_font = QFont("Courier New", 9)

        for row_idx, ev in enumerate(filtered):
            self._event_table.insertRow(row_idx)

            # UTC Time
            t_str = to_iso8601(ev.normalized_timestamp_utc) or "—"
            item_utc = QTableWidgetItem(t_str)
            item_utc.setFont(mono_font)
            item_utc.setForeground(QColor("#7ec8e3"))
            self._event_table.setItem(row_idx, 0, item_utc)

            # Raw / Offset
            off_str = f"{ev.offset_seconds:+.1f}s" if ev.offset_seconds is not None else "0.0s"
            raw_str = f"{ev.raw_timestamp or '—'} ({off_str})"
            item_raw = QTableWidgetItem(raw_str)
            self._event_table.setItem(row_idx, 1, item_raw)

            # Type
            item_type = QTableWidgetItem(ev.event_type)
            if ev.event_type == TimelineEventType.METADATA.value:
                item_type.setForeground(QColor("#fbbf24"))
            elif ev.event_type == TimelineEventType.AI_PRELIMINARY.value:
                item_type.setForeground(QColor("#c084fc"))
            else:
                item_type.setForeground(QColor("#38bdf8"))
            self._event_table.setItem(row_idx, 2, item_type)

            # Status
            item_stat = QTableWidgetItem(ev.analyst_status)
            if ev.analyst_status == AnalystStatus.CONFIRMED.value:
                item_stat.setForeground(QColor("#34d399"))
            elif ev.analyst_status == AnalystStatus.REJECTED.value:
                item_stat.setForeground(QColor("#f87171"))
            else:
                item_stat.setForeground(QColor("#94a3b8"))
            self._event_table.setItem(row_idx, 3, item_stat)

            # Description
            item_desc = QTableWidgetItem(ev.description or "—")
            self._event_table.setItem(row_idx, 4, item_desc)

            # Attach event ID to row
            item_utc.setData(Qt.UserRole, ev.id)

    def _populate_detection_table(self, detections: list[AIDetection]) -> None:
        self._det_table.setRowCount(0)
        mono_font = QFont("Courier New", 9)
        self._all_detections_map = {d.id: d for d in detections}

        for row_idx, d in enumerate(detections):
            self._det_table.insertRow(row_idx)

            # Class
            c_item = QTableWidgetItem(d.class_name.upper())
            c_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            c_item.setForeground(QColor("#c084fc"))
            self._det_table.setItem(row_idx, 0, c_item)

            # Confidence
            conf_pct = f"{d.confidence * 100:.1f}%"
            conf_item = QTableWidgetItem(conf_pct)
            conf_item.setTextAlignment(Qt.AlignCenter)
            self._det_table.setItem(row_idx, 1, conf_item)

            # Timecode
            tc_item = QTableWidgetItem(d.frame_timestamp or f"Frame #{d.frame_number}")
            tc_item.setFont(mono_font)
            self._det_table.setItem(row_idx, 2, tc_item)

            # Review Status
            stat_item = QTableWidgetItem(d.reviewer_status)
            stat_item.setTextAlignment(Qt.AlignCenter)
            if d.reviewer_status == ReviewerStatus.CONFIRMED.value:
                stat_item.setForeground(QColor("#34d399"))
            elif d.reviewer_status == ReviewerStatus.REJECTED.value:
                stat_item.setForeground(QColor("#f87171"))
            else:
                stat_item.setForeground(QColor("#fbbf24"))
            self._det_table.setItem(row_idx, 3, stat_item)

            # Attach detection ID
            c_item.setData(Qt.UserRole, d.id)

    # ─────────────────────────────────────────────────────────────────────────
    # Interactivity & Actions
    # ─────────────────────────────────────────────────────────────────────────

    def _open_video_for_evidence(self, wc_path: Path, segment: VideoSegment) -> None:
        """Initialize OpenCV VideoCapture for working copy."""
        self._stop_playback()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

        self._current_video_path = wc_path
        self._duration_seconds = segment.duration_seconds or 0.0
        res_str = segment.resolution or "N/A"
        codec_str = segment.codec or "N/A"
        if hasattr(self, "_meta_badge"):
            self._meta_badge.setText(f"{res_str} | {codec_str}")

        try:
            import cv2
            cap = cv2.VideoCapture(str(wc_path))
            if cap.isOpened():
                self._cap = cap
                fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
                self._current_fps = max(1.0, float(fps))
                fc = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                if fc <= 0 and self._duration_seconds > 0:
                    fc = int(self._duration_seconds * self._current_fps)
                self._total_frames = max(1, fc)
                if self._duration_seconds <= 0:
                    self._duration_seconds = self._total_frames / self._current_fps

                self._current_position = 0.0
                self._seek_and_render_frame(0.0)
                return
        except Exception as exc:
            logger.warning("Failed to open video %s with cv2: %s", wc_path, exc)

        # Fallback if cv2 cannot open stream directly
        self._render_fallback_card(wc_path, segment)

    def _render_fallback_card(self, wc_path: Path, segment: VideoSegment) -> None:
        """Render high-contrast forensic card when video stream cannot be decoded directly."""
        w = max(360, self._screen_box.width() or 400)
        h = max(220, self._screen_box.height() or 240)
        pixmap = QPixmap(w, h)
        pixmap.fill(QColor("#060b10"))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        painter.setPen(QPen(QColor("#1e3a5f"), 1))
        painter.drawRect(1, 1, w - 2, h - 2)

        painter.setPen(QColor("#7ec8e3"))
        painter.setFont(QFont("Segoe UI", 11, QFont.Bold))
        painter.drawText(QRectF(10, 35, w - 20, 24), Qt.AlignCenter, "▶ FORENSIC EVIDENCE WORKING COPY")

        painter.setPen(QColor("#e8f0fe"))
        painter.setFont(QFont("Segoe UI", 10))
        painter.drawText(QRectF(10, 68, w - 20, 20), Qt.AlignCenter, wc_path.name)

        painter.setPen(QColor("#9aa5b4"))
        painter.setFont(QFont("Segoe UI", 9))
        info_text = f"Format: {segment.codec or 'Raw Stream'}  •  Resolution: {segment.resolution or 'Unknown'}  •  Duration: {self._duration_seconds:.2f}s"
        painter.drawText(QRectF(10, 95, w - 20, 20), Qt.AlignCenter, info_text)

        painter.setPen(QColor("#38bdf8"))
        painter.drawText(QRectF(10, 130, w - 20, 20), Qt.AlignCenter, "Direct stream container. Use Vendor Matrix / Carving to inspect raw stream.")
        painter.end()

        self._last_rendered_pixmap = pixmap
        self._screen_box.setPixmap(pixmap)

    def _seek_and_render_frame(
        self,
        seconds: float,
        bbox: Optional[list[float]] = None,
        bbox_label: Optional[str] = None,
    ) -> None:
        """Seek video capture and render the frame with optional forensic bounding box."""
        seconds = max(0.0, min(self._duration_seconds or 3600.0, float(seconds)))
        self._current_position = seconds

        mins = int(seconds // 60)
        secs = seconds % 60
        tot_mins = int(self._duration_seconds // 60)
        tot_secs = self._duration_seconds % 60
        self._tc_label.setText(f"Position: {mins:02d}:{secs:06.3f} / {tot_mins:02d}:{tot_secs:06.3f}")

        if self._cap is None or not self._cap.isOpened():
            return

        try:
            import cv2
            target_frame = int(seconds * self._current_fps)
            target_frame = max(0, min(self._total_frames - 1, target_frame))
            self._cap.set(cv2.CAP_PROP_POS_FRAMES, target_frame)
            ret, frame = self._cap.read()
            if not ret or frame is None:
                return

            H, W = frame.shape[:2]

            # 1. Draw detection bounding box if provided
            if bbox and len(bbox) >= 4:
                bx = int(bbox[0] * W)
                by = int(bbox[1] * H)
                bw = int(bbox[2] * W)
                bh = int(bbox[3] * H)

                bx = max(0, min(W - 1, bx))
                by = max(0, min(H - 1, by))
                bw = max(1, min(W - bx, bw))
                bh = max(1, min(H - by, bh))

                cv2.rectangle(frame, (bx, by), (bx + bw, by + bh), (0, 240, 255), 3)

                tag_text = bbox_label or "DETECTION"
                font_scale = 0.55
                thickness = 1
                (tw, th), baseline = cv2.getTextSize(tag_text, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)
                tag_y1 = max(0, by - th - 10)
                tag_y2 = by
                tag_x2 = min(W, bx + tw + 12)
                cv2.rectangle(frame, (bx, tag_y1), (tag_x2, tag_y2), (0, 240, 255), -1)
                cv2.putText(
                    frame,
                    tag_text,
                    (bx + 6, tag_y2 - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    font_scale,
                    (0, 0, 0),
                    thickness,
                    cv2.LINE_AA,
                )

            # 2. Forensic Watermark HUD Overlay
            cv2.putText(
                frame,
                "FORENSIQ VAULT - VERIFIED WORKING COPY",
                (16, 26),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (0, 255, 128),
                1,
                cv2.LINE_AA,
            )
            cv2.putText(
                frame,
                f"TC: +{seconds:.3f}s  [Frame {target_frame}/{self._total_frames}]",
                (16, H - 14),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.48,
                (200, 220, 240),
                1,
                cv2.LINE_AA,
            )

            # 3. Convert to QPixmap and display
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            h, w, ch = rgb.shape
            q_img = QImage(rgb.data, w, h, ch * w, QImage.Format_RGB888)
            pixmap = QPixmap.fromImage(q_img)
            self._last_rendered_pixmap = pixmap
            self._update_screen_box_pixmap(pixmap)

        except Exception as exc:
            logger.warning("Error rendering frame at %.2fs: %s", seconds, exc)

    def _update_screen_box_pixmap(self, pixmap: QPixmap) -> None:
        """Scale and set pixmap to screen box keeping aspect ratio."""
        if pixmap and not pixmap.isNull():
            target_size = self._screen_box.size()
            if target_size.width() > 10 and target_size.height() > 10:
                scaled = pixmap.scaled(target_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self._screen_box.setPixmap(scaled)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._last_rendered_pixmap:
            self._update_screen_box_pixmap(self._last_rendered_pixmap)

    def _toggle_playback(self) -> None:
        if self._is_playing:
            self._stop_playback()
        else:
            self._start_playback()

    def _start_playback(self) -> None:
        if not self._cap or not self._cap.isOpened():
            return
        self._is_playing = True
        self._play_btn.setText("⏸ Pause")
        interval = max(10, int(1000 / self._current_fps))
        self._play_timer.start(interval)

    def _stop_playback(self) -> None:
        self._is_playing = False
        self._play_timer.stop()
        if hasattr(self, "_play_btn"):
            self._play_btn.setText("▶ Play")

    def _step_position(self, delta_seconds: float) -> None:
        new_pos = max(0.0, min(self._duration_seconds, self._current_position + delta_seconds))
        self._seek_and_render_frame(new_pos)
        self._timeline_widget.set_current_position(new_pos)

    def _on_play_tick(self) -> None:
        step = 1.0 / self._current_fps
        next_pos = self._current_position + step
        if next_pos >= self._duration_seconds:
            self._stop_playback()
            next_pos = self._duration_seconds

        self._seek_and_render_frame(next_pos)
        self._timeline_widget.set_current_position(next_pos)

    def closeEvent(self, event) -> None:
        self._stop_playback()
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None
        super().closeEvent(event)

    def _on_scrubber_moved(self, seconds: float) -> None:
        self._seek_and_render_frame(seconds)

    def _on_timeline_marker_clicked(self, event_id: str) -> None:
        # Select row in table
        for r in range(self._event_table.rowCount()):
            item = self._event_table.item(r, 0)
            if item and item.data(Qt.UserRole) == event_id:
                self._event_table.selectRow(r)
                self._event_table.scrollToItem(item)
                break
        for ev in getattr(self, "_all_events", []):
            if ev.id == event_id and ev.offset_seconds is not None:
                self._seek_and_render_frame(ev.offset_seconds)
                break

    def _on_table_selection_changed(self) -> None:
        row = self._event_table.currentRow()
        if row >= 0:
            item = self._event_table.item(row, 0)
            if item:
                ev_id = item.data(Qt.UserRole)
                # Find event offset to jump scrubber
                for ev in getattr(self, "_all_events", []):
                    if ev.id == ev_id and ev.offset_seconds is not None:
                        self._timeline_widget.set_current_position(ev.offset_seconds)
                        self._seek_and_render_frame(ev.offset_seconds)
                        break

    def _on_detection_selected(self) -> None:
        row = self._det_table.currentRow()
        if row >= 0:
            item = self._det_table.item(row, 0)
            if item:
                det_id = item.data(Qt.UserRole)
                self._selected_detection_id = det_id
                self._confirm_btn.setEnabled(True)
                self._reject_btn.setEnabled(True)

                d = self._all_detections_map.get(det_id)
                if d:
                    sec = 0.0
                    if d.frame_timestamp and d.frame_timestamp.startswith("+") and d.frame_timestamp.endswith("s"):
                        try:
                            sec = float(d.frame_timestamp[1:-1])
                        except ValueError:
                            sec = (d.frame_number / self._current_fps) if self._current_fps > 0 else 0.0
                    elif self._current_fps > 0:
                        sec = d.frame_number / self._current_fps

                    bbox = None
                    if d.bbox_json:
                        try:
                            bbox = json.loads(d.bbox_json)
                        except Exception:
                            bbox = None

                    label = f"{d.class_name.upper()} {int(d.confidence * 100)}%"
                    self._timeline_widget.set_current_position(sec)
                    self._seek_and_render_frame(sec, bbox=bbox, bbox_label=label)
                return

        self._selected_detection_id = None
        self._confirm_btn.setEnabled(False)
        self._reject_btn.setEnabled(False)

    def _review_current_detection(self, new_status: str) -> None:
        if not self._selected_detection_id:
            return

        session = get_session()
        try:
            review_detection(
                session=session,
                detection_id=self._selected_detection_id,
                reviewer_status=new_status,
                reviewer_id="Investigator",
            )
            QMessageBox.information(
                self,
                "Review Recorded",
                f"Detection status updated to {new_status}. Recorded into chain of custody.",
            )
            if self._selected_evidence_id:
                self._load_timeline_data(self._selected_evidence_id)
        except Exception as exc:
            QMessageBox.critical(self, "Review Error", str(exc))
        finally:
            session.close()

    def _apply_normalization(self) -> None:
        if not self._selected_evidence_id:
            QMessageBox.warning(self, "No Evidence Selected", "Please select an evidence item first.")
            return

        val = self._offset_spin.value()
        sign = 1.0 if "+" in self._sign_combo.currentText() else -1.0
        offset = val * sign
        method = self._method_combo.currentText()

        session = get_session()
        try:
            apply_timestamp_normalization(
                session=session,
                evidence_id=self._selected_evidence_id,
                offset_seconds=offset,
                method=method,
                actor_id="Investigator",
            )
            QMessageBox.information(
                self,
                "Normalization Applied",
                f"Successfully shifted timeline by {offset:+.1f}s ({method}).\n"
                "Custody action TIMESTAMP_NORMALIZATION_APPLIED recorded.",
            )
            self._load_timeline_data(self._selected_evidence_id)
        except Exception as exc:
            QMessageBox.critical(self, "Normalization Error", str(exc))
        finally:
            session.close()

    def _start_ai_triage(self) -> None:
        if not self._selected_segment_id:
            QMessageBox.warning(self, "No Segment Ready", "Please select an evidence item with parsed stream data.")
            return

        self._triage_btn.setEnabled(False)
        self._progress_bar.setVisible(True)

        self._triage_worker = AITriageWorker(self._selected_segment_id)
        self._triage_worker.triage_finished.connect(self._on_triage_finished)
        self._triage_worker.start()

    def _on_triage_finished(self, success: bool, count: int, error_msg: str) -> None:
        self._progress_bar.setVisible(False)
        self._triage_btn.setEnabled(True)

        if not success:
            QMessageBox.critical(self, "AI Triage Failed", error_msg)
            return

        QMessageBox.information(
            self,
            "AI Triage Complete",
            f"Generated {count} candidate forensic detections.\n"
            "All detections are marked PENDING and require human analyst confirmation.",
        )
        if self._selected_evidence_id:
            self._load_timeline_data(self._selected_evidence_id)

    def _export_json(self) -> None:
        active_case_id = self._main_window.active_case_id
        if not active_case_id:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Timeline JSON", "timeline_export.json", "JSON Files (*.json)")
        if not path:
            return
        session = get_session()
        try:
            data = export_timeline_json(session, active_case_id)
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            QMessageBox.information(self, "Export Complete", f"Timeline JSON exported to:\n{path}")
        finally:
            session.close()

    def _export_csv(self) -> None:
        active_case_id = self._main_window.active_case_id
        if not active_case_id:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Timeline CSV", "timeline_export.csv", "CSV Files (*.csv)")
        if not path:
            return
        session = get_session()
        try:
            data = export_timeline_csv(session, active_case_id)
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            QMessageBox.information(self, "Export Complete", f"Timeline CSV exported to:\n{path}")
        finally:
            session.close()
