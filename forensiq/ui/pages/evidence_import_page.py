"""
forensiq/ui/pages/evidence_import_page.py
-------------------------------------------
Evidence Import page.

Layout:
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ⚠ FORENSIC NOTICE (amber warning panel)                               │
  ├──────────────────────────┬──────────────────────────────────────────────┤
  │  IMPORT FORM             │  EVIDENCE LIST (this case)                   │
  │  [Browse…]               │  ┌──────────────────────────────────────────┐│
  │  File path display       │  │ EvidenceTable                            ││
  │  File size / ext         │  │                                          ││
  │  Evidence №              │  └──────────────────────────────────────────┘│
  │  Investigator            │                                              │
  │  Description             │                                              │
  │  [Import Evidence]       │                                              │
  │  Progress bar            │                                              │
  │  Status label            │                                              │
  └──────────────────────────┴──────────────────────────────────────────────┘

The import operation runs in ImportWorker (QThread) to keep UI responsive.

Phase 2: Fully implemented.
"""

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.services.evidence_service import EvidenceImportError, ImportResult, import_evidence
from forensiq.services.case_service import get_case_by_id
from forensiq.ui.widgets.evidence_table import EvidenceTable
from forensiq.ui.widgets.warning_panel import ErrorPanel, WarningPanel


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread — runs import_evidence() off the main thread
# ─────────────────────────────────────────────────────────────────────────────

class ImportWorker(QThread):
    """QThread that runs the evidence import pipeline."""

    progress = Signal(str, int, int)      # step_label, bytes_done, bytes_total
    finished = Signal(object)             # ImportResult or None on success
    failed = Signal(str)                  # error message

    def __init__(self, case_id: str, source_path: Path, investigator: str,
                 evidence_number: Optional[str], description: Optional[str]):
        super().__init__()
        self._case_id = case_id
        self._source = source_path
        self._investigator = investigator
        self._ev_number = evidence_number
        self._description = description

    def run(self) -> None:
        def _progress_cb(label: str, done: int, total: int) -> None:
            self.progress.emit(label, done, total)

        try:
            result = import_evidence(
                case_id=self._case_id,
                source_path=self._source,
                investigator=self._investigator,
                evidence_number=self._ev_number or None,
                description=self._description or None,
                progress_cb=_progress_cb,
            )
            self.finished.emit(result)
        except EvidenceImportError as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f"Unexpected error during import:\n{e}")


# ─────────────────────────────────────────────────────────────────────────────
# Page
# ─────────────────────────────────────────────────────────────────────────────

def _format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class EvidenceImportPage(QWidget):
    """Page for importing evidence files into the active case."""

    # Emitted when an evidence item should be opened in the detail page
    evidence_open_requested = Signal(str)  # evidence_id

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._selected_path: Optional[Path] = None
        self._worker: Optional[ImportWorker] = None

        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # Page header
        header = QLabel("📥  Evidence Import")
        header.setStyleSheet("color: #e8f0fe; font-size: 20px; font-weight: bold;")
        root.addWidget(header)

        # Mandatory forensic warning
        root.addWidget(WarningPanel(
            "FORENSIC NOTICE — Only import evidence that has been lawfully obtained "
            "and authorised. This tool copies files; it does not move or delete them. "
            "Imported originals are stored read-only in the vault. "
            "All analysis runs on a verified working copy only."
        ))

        # No-case warning (shown when no case is active)
        self._no_case_panel = ErrorPanel(
            "No case is currently open. Please open or create a case first."
        )
        root.addWidget(self._no_case_panel)

        # Splitter: form (left) | evidence list (right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle { background: #1e3a5f; }")
        root.addWidget(splitter)

        # ── LEFT: Import form ────────────────────────────────────────────────
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 8, 0)
        form_layout.setSpacing(12)

        form_card = QFrame()
        form_card.setStyleSheet(
            "QFrame { background: #0d1821; border: 1px solid #1e3a5f; border-radius: 8px; }"
        )
        card_layout = QVBoxLayout(form_card)
        card_layout.setContentsMargins(20, 16, 20, 16)
        card_layout.setSpacing(14)

        # File selection
        file_label = QLabel("Select Evidence File")
        file_label.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 13px;")
        card_layout.addWidget(file_label)

        browse_row = QHBoxLayout()
        self._file_path_label = QLabel("No file selected")
        self._file_path_label.setStyleSheet(
            "color: #9aa5b4; background: #12181f; padding: 6px 10px; "
            "border-radius: 4px; border: 1px solid #2d4a6a;"
        )
        self._file_path_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._file_path_label.setWordWrap(True)
        browse_row.addWidget(self._file_path_label)

        browse_btn = QPushButton("Browse…")
        browse_btn.setFixedWidth(90)
        browse_btn.setStyleSheet(
            "QPushButton { background: #1e3a5f; color: #7ec8e3; "
            "border: 1px solid #2d6a9f; border-radius: 4px; padding: 6px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        browse_btn.clicked.connect(self._browse_file)
        browse_row.addWidget(browse_btn)
        card_layout.addLayout(browse_row)

        self._file_info_label = QLabel("")
        self._file_info_label.setStyleSheet("color: #6b7280; font-size: 10px;")
        card_layout.addWidget(self._file_info_label)

        # Form fields
        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight)

        lbl_style = "color: #9aa5b4; font-size: 11px;"
        field_style = (
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 5px 8px;"
        )

        self._ev_number_input = QLineEdit()
        self._ev_number_input.setPlaceholderText("Auto-generated if blank (e.g. EVD-0001)")
        self._ev_number_input.setStyleSheet(field_style)
        ev_lbl = QLabel("Evidence №:")
        ev_lbl.setStyleSheet(lbl_style)
        form.addRow(ev_lbl, self._ev_number_input)

        self._investigator_input = QLineEdit()
        self._investigator_input.setPlaceholderText("Full investigator name")
        self._investigator_input.setStyleSheet(field_style)
        inv_lbl = QLabel("Investigator:")
        inv_lbl.setStyleSheet(lbl_style)
        form.addRow(inv_lbl, self._investigator_input)

        self._description_input = QTextEdit()
        self._description_input.setPlaceholderText("Optional: exhibit note, source device description…")
        self._description_input.setFixedHeight(70)
        self._description_input.setStyleSheet(field_style)
        desc_lbl = QLabel("Description:")
        desc_lbl.setStyleSheet(lbl_style)
        form.addRow(desc_lbl, self._description_input)

        card_layout.addLayout(form)

        # Import button
        self._import_btn = QPushButton("⬇  Import Evidence")
        self._import_btn.setEnabled(False)
        self._import_btn.setFixedHeight(38)
        self._import_btn.setStyleSheet(
            "QPushButton { background: #1e5b8a; color: #e8f0fe; font-weight: bold; "
            "border: 1px solid #2d6a9f; border-radius: 6px; font-size: 13px; }"
            "QPushButton:hover { background: #2a7ab5; }"
            "QPushButton:disabled { background: #1e2d3d; color: #4b5563; "
            "border-color: #374151; }"
        )
        self._import_btn.clicked.connect(self._start_import)
        card_layout.addWidget(self._import_btn)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(10)
        self._progress_bar.setStyleSheet(
            "QProgressBar { background: #12181f; border: 1px solid #1e3a5f; border-radius: 5px; }"
            "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 #1e5b8a, stop:1 #34d399); border-radius: 5px; }"
        )
        card_layout.addWidget(self._progress_bar)

        # Status label
        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #9aa5b4; font-size: 10px;")
        self._status_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self._status_label)

        form_layout.addWidget(form_card)
        form_layout.addStretch()
        splitter.addWidget(form_container)

        # ── RIGHT: Evidence list ─────────────────────────────────────────────
        list_container = QWidget()
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(8, 0, 0, 0)
        list_layout.setSpacing(8)

        list_title = QLabel("Evidence in This Case")
        list_title.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 13px;")
        list_layout.addWidget(list_title)

        self._evidence_table = EvidenceTable()
        self._evidence_table.evidence_selected.connect(self.evidence_open_requested)
        list_layout.addWidget(self._evidence_table)
        splitter.addWidget(list_container)

        splitter.setSizes([420, 640])

    def set_active_case(self, case_id: Optional[str]) -> None:
        """Called by MainWindow when the active case changes."""
        has_case = bool(case_id)
        self._no_case_panel.setVisible(not has_case)
        self._import_btn.setEnabled(has_case and self._selected_path is not None)
        self.refresh()

    def refresh(self) -> None:
        """Reload the evidence list for the active case."""
        case_id = self._main_window.active_case_id
        if not case_id:
            self._evidence_table.load([])
            no_case = True
        else:
            from forensiq.services.evidence_service import list_evidence
            items = list_evidence(case_id)
            self._evidence_table.load(items)
            no_case = False
        self._no_case_panel.setVisible(no_case)
        self._import_btn.setEnabled(not no_case and self._selected_path is not None)

    # ─── File selection ───────────────────────────────────────────────────────

    def _browse_file(self) -> None:
        from forensiq.config import ALLOWED_EXTENSIONS
        ext_str = " ".join(f"*{e}" for e in sorted(ALLOWED_EXTENSIONS))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Evidence File",
            "",
            f"Video Evidence ({ext_str});;All Files (*)",
        )
        if not path:
            return

        p = Path(path)
        self._selected_path = p
        # Show truncated path
        display = str(p) if len(str(p)) < 80 else f"…{str(p)[-78:]}"
        self._file_path_label.setText(display)

        # File info
        try:
            size = p.stat().st_size
            size_str = self._format_size_local(size)
        except OSError:
            size_str = "unknown size"
        self._file_info_label.setText(f"Extension: {p.suffix.lower()}  |  Size: {size_str}")

        self._import_btn.setEnabled(bool(self._main_window.active_case_id))

    @staticmethod
    def _format_size_local(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # ─── Import workflow ──────────────────────────────────────────────────────

    def _start_import(self) -> None:
        case_id = self._main_window.active_case_id
        if not case_id or not self._selected_path:
            return

        investigator = self._investigator_input.text().strip()
        if not investigator:
            QMessageBox.warning(self, "Missing Information", "Please enter an investigator name.")
            return

        ev_number = self._ev_number_input.text().strip() or None
        description = self._description_input.toPlainText().strip() or None

        # UI lock
        self._import_btn.setEnabled(False)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(True)
        self._status_label.setText("Starting import…")

        # Launch worker
        self._worker = ImportWorker(
            case_id=case_id,
            source_path=self._selected_path,
            investigator=investigator,
            evidence_number=ev_number,
            description=description,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_progress(self, label: str, done: int, total: int) -> None:
        self._status_label.setText(label)
        if total > 0:
            pct = int(done * 100 / total)
            self._progress_bar.setValue(pct)

    def _on_finished(self, result: object) -> None:
        from forensiq.services.evidence_service import ImportResult as IR
        r: IR = result
        self._progress_bar.setValue(100)
        self._status_label.setText(
            f"✔ Import complete — {r.evidence_number}  |  SHA-256: {r.original_sha256[:16]}…"
        )
        # Reset form
        self._selected_path = None
        self._file_path_label.setText("No file selected")
        self._file_info_label.setText("")
        self._ev_number_input.clear()
        self._description_input.clear()
        self._import_btn.setEnabled(False)
        self.refresh()

    def _on_failed(self, message: str) -> None:
        self._progress_bar.setVisible(False)
        self._status_label.setText("")
        case_id = self._main_window.active_case_id
        self._import_btn.setEnabled(bool(case_id) and bool(self._selected_path))
        QMessageBox.critical(
            self,
            "Import Failed",
            f"Evidence import failed:\n\n{message}",
        )
