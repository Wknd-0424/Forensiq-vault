"""
forensiq/ui/pages/evidence_detail_page.py
-------------------------------------------
Evidence Detail page — shows full integrity info for a selected evidence item.

Layout:
  ┌─────────────────────────────────────────────────────┐
  │  ← Back   [Evidence #] [Status Badge]   [Case]     │
  ├────────────────────────┬────────────────────────────┤
  │  HashCard (SHA-256+MD5)│  Vault paths               │
  │                        │  Read-only indicator        │
  │  [Verify Integrity]    │  Working copy path          │
  │  Verify status label   │  Manifest path             │
  ├────────────────────────┴────────────────────────────┤
  │  Custody Events (for this evidence, first 10)       │
  └─────────────────────────────────────────────────────┘

Phase 2: Fully implemented.
"""

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from forensiq.config import VAULT_ROOT
from forensiq.constants import EvidenceStatus
from forensiq.models.evidence import EvidenceItem
from forensiq.ui.widgets.hash_card import HashCard
from forensiq.ui.widgets.status_badge import StatusBadge


# ─────────────────────────────────────────────────────────────────────────────
# Verify worker
# ─────────────────────────────────────────────────────────────────────────────

class VerifyWorker(QThread):
    """Re-hash the working copy and compare against stored SHA-256."""
    result = Signal(bool, str)   # match, actual_sha256

    def __init__(self, working_copy_path: Path, expected_sha256: str):
        super().__init__()
        self._path = working_copy_path
        self._expected = expected_sha256

    def run(self) -> None:
        from forensiq.utils.hashing import HashingError, hash_file
        try:
            hr = hash_file(self._path)
            match = hr.sha256.lower() == self._expected.lower()
            self.result.emit(match, hr.sha256)
        except HashingError as e:
            self.result.emit(False, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Detail page
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceDetailPage(QWidget):
    """Full integrity detail view for a single evidence item."""

    back_requested = Signal()   # emitted by the ← Back button

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._evidence_id: Optional[str] = None
        self._evidence: Optional[EvidenceItem] = None
        self._verify_worker: Optional[VerifyWorker] = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header ─────────────────────────────────────────────────────────
        header_row = QHBoxLayout()
        back_btn = QPushButton("← Back")
        back_btn.setFixedWidth(80)
        back_btn.setStyleSheet(
            "QPushButton { background: #1e2d3d; color: #7ec8e3; "
            "border: 1px solid #2d4a6a; border-radius: 4px; padding: 5px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        back_btn.clicked.connect(self.back_requested)
        header_row.addWidget(back_btn)

        self._ev_number_label = QLabel("—")
        self._ev_number_label.setStyleSheet(
            "color: #e8f0fe; font-size: 18px; font-weight: bold; margin-left: 12px;"
        )
        header_row.addWidget(self._ev_number_label)

        self._status_badge = StatusBadge("IMPORTED")
        header_row.addWidget(self._status_badge)

        header_row.addStretch()

        self._case_label = QLabel("")
        self._case_label.setStyleSheet("color: #6b7280; font-size: 11px;")
        header_row.addWidget(self._case_label)
        root.addLayout(header_row)

        # ── Scrollable content ─────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)

        # ── Top panel: hashes + vault paths ───────────────────────────────
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        # Hash card + verify button (left column)
        hash_col = QVBoxLayout()
        self._hash_card = HashCard()
        hash_col.addWidget(self._hash_card)

        verify_row = QHBoxLayout()
        self._verify_btn = QPushButton("🔍  Verify Integrity")
        self._verify_btn.setEnabled(False)
        self._verify_btn.setFixedHeight(34)
        self._verify_btn.setStyleSheet(
            "QPushButton { background: #1e3a5f; color: #7ec8e3; "
            "border: 1px solid #2d6a9f; border-radius: 5px; font-size: 12px; }"
            "QPushButton:hover { background: #2a4a6a; }"
            "QPushButton:disabled { background: #1e2d3d; color: #4b5563; border-color: #374151; }"
        )
        self._verify_btn.clicked.connect(self._start_verify)
        verify_row.addWidget(self._verify_btn)

        self._verify_status = QLabel("")
        self._verify_status.setStyleSheet("font-size: 11px; margin-left: 8px;")
        verify_row.addWidget(self._verify_status)
        verify_row.addStretch()
        hash_col.addLayout(verify_row)
        hash_col.addStretch()
        top_row.addLayout(hash_col, stretch=3)

        # Vault paths panel (right column)
        paths_frame = QFrame()
        paths_frame.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 8px; }"
        )
        paths_layout = QVBoxLayout(paths_frame)
        paths_layout.setContentsMargins(16, 12, 16, 12)
        paths_layout.setSpacing(10)

        paths_title = QLabel("🗄  Vault Storage")
        paths_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 13px;")
        paths_layout.addWidget(paths_title)

        self._orig_path_label = self._make_path_label()
        self._wc_path_label = self._make_path_label()
        self._manifest_label = self._make_path_label()
        self._read_only_label = QLabel("")
        self._read_only_label.setStyleSheet("font-size: 11px;")

        paths_layout.addWidget(QLabel("Original (read-only):"), )
        paths_layout.addWidget(self._orig_path_label)
        paths_layout.addWidget(self._read_only_label)
        paths_layout.addWidget(QLabel("Working copy:"))
        paths_layout.addWidget(self._wc_path_label)
        paths_layout.addWidget(QLabel("Manifest:"))
        paths_layout.addWidget(self._manifest_label)

        for lbl in paths_layout.children():
            if isinstance(lbl, QLabel) and lbl not in (
                paths_title, self._orig_path_label,
                self._wc_path_label, self._manifest_label,
                self._read_only_label,
            ):
                lbl.setStyleSheet("color: #6b7280; font-size: 10px; margin-top: 4px;")

        top_row.addWidget(paths_frame, stretch=2)
        content_layout.addLayout(top_row)

        # ── Custody mini-table ─────────────────────────────────────────────
        custody_frame = QFrame()
        custody_frame.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 8px; }"
        )
        custody_layout = QVBoxLayout(custody_frame)
        custody_layout.setContentsMargins(16, 12, 16, 12)
        custody_layout.setSpacing(8)

        custody_title = QLabel("🔗  Custody Events (this evidence)")
        custody_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 13px;")
        custody_layout.addWidget(custody_title)

        from forensiq.ui.widgets.custody_table import CustodyTable
        self._custody_table = CustodyTable(max_rows=10)
        custody_layout.addWidget(self._custody_table)
        content_layout.addWidget(custody_frame)

        content_layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll)

    @staticmethod
    def _make_path_label() -> QLabel:
        lbl = QLabel("—")
        from PySide6.QtGui import QFont
        mono = QFont("Courier New", 9)
        lbl.setFont(mono)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            "color: #9aa5b4; background: #12181f; padding: 4px 8px; "
            "border-radius: 3px; border: 1px solid #1e2d3d;"
        )
        return lbl

    # ─── Load evidence item ───────────────────────────────────────────────────

    def load_evidence(self, evidence_id: str) -> None:
        """Load and display the evidence item with the given UUID."""
        from forensiq.services.evidence_service import get_evidence_by_id
        self._evidence_id = evidence_id
        self._evidence = get_evidence_by_id(evidence_id)
        self._populate()

    def refresh(self) -> None:
        if self._evidence_id:
            self.load_evidence(self._evidence_id)

    def _populate(self) -> None:
        ev = self._evidence
        if not ev:
            return

        self._ev_number_label.setText(f"Evidence {ev.evidence_number}")
        self._status_badge.set_status(ev.status or "IMPORTED")

        # Hash card
        self._hash_card.set_hashes(ev.original_sha256 or "", ev.original_md5 or "")

        # Vault paths
        orig_rel = ev.original_relative_path or ""
        orig_abs = str(VAULT_ROOT / orig_rel) if orig_rel else "—"
        self._orig_path_label.setText(orig_abs)

        # Working copy — query the latest
        wc_path = "—"
        wc_sha = None
        try:
            from forensiq.database import get_session
            from forensiq.models.evidence import WorkingCopy
            session = get_session()
            wc = session.query(WorkingCopy).filter_by(evidence_id=ev.id).first()
            session.close()
            if wc:
                wc_path = str(VAULT_ROOT / wc.relative_path)
                wc_sha = wc.sha256
        except Exception:
            pass
        self._wc_path_label.setText(wc_path)

        # Manifest path
        if orig_rel:
            base = VAULT_ROOT / ev.case_id / "evidence" / ev.id
            self._manifest_label.setText(str(base / "manifest.json"))
        else:
            self._manifest_label.setText("—")

        # Verify button enabled only if working copy exists
        wc_exists = wc_path != "—" and Path(wc_path).exists()
        self._verify_btn.setEnabled(wc_exists and bool(ev.original_sha256))
        self._verify_btn.setProperty("_wc_path", wc_path)
        self._verify_btn.setProperty("_expected_sha256", ev.original_sha256 or "")

        # Read-only indicator
        if orig_abs != "—":
            try:
                import os, stat
                mode = os.stat(orig_abs).st_mode
                is_ro = not (mode & stat.S_IWUSR)
                if is_ro:
                    self._read_only_label.setText("🔒 Read-only")
                    self._read_only_label.setStyleSheet("color: #34d399; font-size: 10px;")
                else:
                    self._read_only_label.setText("⚠ Not read-only")
                    self._read_only_label.setStyleSheet("color: #f59e0b; font-size: 10px;")
            except OSError:
                self._read_only_label.setText("? Unknown")
                self._read_only_label.setStyleSheet("color: #6b7280; font-size: 10px;")
        else:
            self._read_only_label.setText("")

        # Custody events for this evidence
        try:
            from forensiq.database import get_session
            from forensiq.models.custody import CustodyEvent
            session = get_session()
            events = (
                session.query(CustodyEvent)
                .filter_by(evidence_id=ev.id)
                .order_by(CustodyEvent.action_timestamp_utc)
                .limit(10)
                .all()
            )
            session.close()
            self._custody_table.load(events)
        except Exception:
            pass

    # ─── Integrity verify ─────────────────────────────────────────────────────

    def _start_verify(self) -> None:
        wc_path = Path(self._verify_btn.property("_wc_path") or "")
        expected = self._verify_btn.property("_expected_sha256") or ""
        if not wc_path.exists() or not expected:
            return

        self._verify_btn.setEnabled(False)
        self._verify_status.setText("Verifying…")
        self._verify_status.setStyleSheet("color: #9aa5b4; font-size: 11px;")

        self._verify_worker = VerifyWorker(wc_path, expected)
        self._verify_worker.result.connect(self._on_verify_result)
        self._verify_worker.start()

    def _on_verify_result(self, match: bool, actual: str) -> None:
        self._verify_btn.setEnabled(True)
        if match:
            self._hash_card.set_status(HashCard.VERIFIED)
            self._verify_status.setText("✔ VERIFIED — Working copy matches original")
            self._verify_status.setStyleSheet("color: #34d399; font-size: 11px;")
        else:
            self._hash_card.set_status(HashCard.MISMATCH)
            self._verify_status.setText(f"✖ MISMATCH — Got: {actual[:16]}…")
            self._verify_status.setStyleSheet("color: #f87171; font-size: 11px;")
            QMessageBox.critical(
                self,
                "Integrity Mismatch",
                "⚠ CRITICAL — Working copy hash does NOT match the original.\n\n"
                "The working copy may have been modified or corrupted.\n"
                "Do not use this copy for any further analysis.\n\n"
                f"Expected: {self._verify_btn.property('_expected_sha256')}\n"
                f"Got:      {actual}",
            )
