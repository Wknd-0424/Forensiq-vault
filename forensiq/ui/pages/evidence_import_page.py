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
    QCheckBox,
    QComboBox,
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
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.services.evidence_service import EvidenceImportError, ImportResult, import_evidence
from forensiq.services.imaging_service import ImagingError, ImagingResult, create_forensic_image
from forensiq.services.case_service import get_case_by_id
from forensiq.ui.widgets.evidence_table import EvidenceTable
from forensiq.ui.widgets.warning_panel import ErrorPanel, WarningPanel


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread — runs create_forensic_image() off the main thread
# ─────────────────────────────────────────────────────────────────────────────

class ImagingWorker(QThread):
    """QThread that executes the sequential bit-stream forensic imaging pipeline."""

    progress = Signal(str, int, int)      # step_label, bytes_done, bytes_total
    finished = Signal(object)             # ImagingResult on success
    failed = Signal(str)                  # error message

    def __init__(
        self,
        case_id: str,
        source_path: Path,
        investigator: str,
        evidence_number: Optional[str],
        description: Optional[str],
        block_size: int,
        simulated_write_blocked: bool,
    ):
        super().__init__()
        self._case_id = case_id
        self._source = source_path
        self._investigator = investigator
        self._ev_number = evidence_number
        self._description = description
        self._block_size = block_size
        self._simulated = simulated_write_blocked

    def run(self) -> None:
        def _progress_cb(label: str, done: int, total: int) -> None:
            self.progress.emit(label, done, total)

        try:
            result = create_forensic_image(
                source_path=self._source,
                case_id=self._case_id,
                investigator=self._investigator,
                evidence_number=self._ev_number or None,
                description=self._description or None,
                block_size=self._block_size,
                progress_cb=_progress_cb,
                simulated_write_blocked=self._simulated,
            )
            self.finished.emit(result)
        except ImagingError as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f"Unexpected error during forensic imaging:\n{e}")


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

        # ── LEFT: Tabs (File Ingestion vs Forensic Imaging) ─────────────────
        form_container = QWidget()
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 8, 0)
        form_layout.setSpacing(8)

        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #1e3a5f; background: #0d1821; border-radius: 8px; }"
            "QTabBar::tab { background: #12181f; color: #9aa5b4; padding: 8px 14px; "
            "border: 1px solid #1e3a5f; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; font-weight: bold; font-size: 11px; }"
            "QTabBar::tab:selected { background: #0d1821; color: #7ec8e3; border-color: #2d6a9f; border-bottom: 2px solid #38bdf8; }"
            "QTabBar::tab:hover { background: #1a2332; color: #e8f0fe; }"
        )

        lbl_style = "color: #9aa5b4; font-size: 11px;"
        field_style = (
            "background: #12181f; color: #e8f0fe; border: 1px solid #2d4a6a; "
            "border-radius: 4px; padding: 5px 8px;"
        )

        # ── TAB 1: Standard File Ingestion ───────────────────────────────────
        tab1_widget = QWidget()
        card_layout = QVBoxLayout(tab1_widget)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(12)

        file_label = QLabel("Select Evidence File (Exported Video / Stream)")
        file_label.setStyleSheet("color: #7ec8e3; font-weight: bold; font-size: 12px;")
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
        self._description_input.setFixedHeight(60)
        self._description_input.setStyleSheet(field_style)
        desc_lbl = QLabel("Description:")
        desc_lbl.setStyleSheet(lbl_style)
        form.addRow(desc_lbl, self._description_input)

        card_layout.addLayout(form)

        self._import_btn = QPushButton("⬇  Import Evidence File")
        self._import_btn.setEnabled(False)
        self._import_btn.setFixedHeight(36)
        self._import_btn.setStyleSheet(
            "QPushButton { background: #1e5b8a; color: #e8f0fe; font-weight: bold; "
            "border: 1px solid #2d6a9f; border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #2a7ab5; }"
            "QPushButton:disabled { background: #1e2d3d; color: #4b5563; border-color: #374151; }"
        )
        self._import_btn.clicked.connect(self._start_import)
        card_layout.addWidget(self._import_btn)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(8)
        self._progress_bar.setStyleSheet(
            "QProgressBar { background: #12181f; border: 1px solid #1e3a5f; border-radius: 4px; }"
            "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 #1e5b8a, stop:1 #34d399); border-radius: 4px; }"
        )
        card_layout.addWidget(self._progress_bar)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #9aa5b4; font-size: 10px;")
        self._status_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self._status_label)
        card_layout.addStretch()

        self._tab_widget.addTab(tab1_widget, "📁 File Ingestion")

        # ── TAB 2: Forensic Imaging (Bit-Stream Acquisition) ─────────────────
        tab2_widget = QWidget()
        img_layout = QVBoxLayout(tab2_widget)
        img_layout.setContentsMargins(16, 14, 16, 14)
        img_layout.setSpacing(10)

        img_header_box = QHBoxLayout()
        img_label = QLabel("Physical Storage Seizure / Raw Bit-Stream Image (.img)")
        img_label.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 12px;")
        img_header_box.addWidget(img_label)

        self._img_demo_btn = QPushButton("⚡ Load EX04 Demo Dump")
        self._img_demo_btn.setFixedHeight(24)
        self._img_demo_btn.setStyleSheet(
            "QPushButton { background: #0284c7; color: #ffffff; font-size: 10px; font-weight: bold; "
            "border: 1px solid #38bdf8; border-radius: 4px; padding: 2px 8px; }"
            "QPushButton:hover { background: #0369a1; }"
        )
        self._img_demo_btn.clicked.connect(self._load_demo_raw_dump)
        img_header_box.addWidget(self._img_demo_btn)
        img_layout.addLayout(img_header_box)

        # Source row
        img_browse_row = QHBoxLayout()
        self._img_path_label = QLabel("No raw device or dump selected")
        self._img_path_label.setStyleSheet(
            "color: #9aa5b4; background: #12181f; padding: 6px 10px; "
            "border-radius: 4px; border: 1px solid #2d4a6a;"
        )
        self._img_path_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._img_path_label.setWordWrap(True)
        img_browse_row.addWidget(self._img_path_label)

        img_browse_btn = QPushButton("Browse…")
        img_browse_btn.setFixedWidth(90)
        img_browse_btn.setStyleSheet(
            "QPushButton { background: #1e3a5f; color: #7ec8e3; "
            "border: 1px solid #2d6a9f; border-radius: 4px; padding: 6px; }"
            "QPushButton:hover { background: #2a4a6a; }"
        )
        img_browse_btn.clicked.connect(self._browse_image_source)
        img_browse_row.addWidget(img_browse_btn)
        img_layout.addLayout(img_browse_row)

        self._img_info_label = QLabel("")
        self._img_info_label.setStyleSheet("color: #6b7280; font-size: 10px;")
        img_layout.addWidget(self._img_info_label)

        # Options
        self._img_write_block_cb = QCheckBox("Simulated Write-Blocked Acquisition (Hardware Protection Invariant)")
        self._img_write_block_cb.setChecked(True)
        self._img_write_block_cb.setStyleSheet("color: #34d399; font-size: 11px; font-weight: bold;")
        img_layout.addWidget(self._img_write_block_cb)

        # Imaging form
        img_form = QFormLayout()
        img_form.setSpacing(8)
        img_form.setLabelAlignment(Qt.AlignRight)

        self._img_block_combo = QComboBox()
        self._img_block_combo.addItems([
            "64 KB (65,536 bytes) — Forensic Standard",
            "128 KB (131,072 bytes) — High Speed",
            "512 KB (524,288 bytes) — High Capacity Disk",
            "4 KB (4,096 bytes) — Direct Sector Aligned",
        ])
        self._img_block_combo.setStyleSheet(field_style)
        block_lbl = QLabel("Block Size:")
        block_lbl.setStyleSheet(lbl_style)
        img_form.addRow(block_lbl, self._img_block_combo)

        self._img_ev_number_input = QLineEdit()
        self._img_ev_number_input.setPlaceholderText("Auto-generated if blank (e.g. EVD-0001)")
        self._img_ev_number_input.setStyleSheet(field_style)
        img_ev_lbl = QLabel("Evidence №:")
        img_ev_lbl.setStyleSheet(lbl_style)
        img_form.addRow(img_ev_lbl, self._img_ev_number_input)

        self._img_investigator_input = QLineEdit()
        self._img_investigator_input.setPlaceholderText("Forensic Examiner Name")
        self._img_investigator_input.setStyleSheet(field_style)
        img_inv_lbl = QLabel("Examiner:")
        img_inv_lbl.setStyleSheet(lbl_style)
        img_form.addRow(img_inv_lbl, self._img_investigator_input)

        self._img_description_input = QTextEdit()
        self._img_description_input.setPlaceholderText("Seizure location, drive serial number, write-block bridge model…")
        self._img_description_input.setFixedHeight(50)
        self._img_description_input.setStyleSheet(field_style)
        img_desc_lbl = QLabel("Seizure Note:")
        img_desc_lbl.setStyleSheet(lbl_style)
        img_form.addRow(img_desc_lbl, self._img_description_input)

        img_layout.addLayout(img_form)

        # Acquire Button
        self._acquire_btn = QPushButton("🛡️  Acquire Forensic Bit-Stream Image (.img)")
        self._acquire_btn.setEnabled(False)
        self._acquire_btn.setFixedHeight(36)
        self._acquire_btn.setStyleSheet(
            "QPushButton { background: #059669; color: #ffffff; font-weight: bold; "
            "border: 1px solid #10b981; border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #10b981; }"
            "QPushButton:disabled { background: #1e2d3d; color: #4b5563; border-color: #374151; }"
        )
        self._acquire_btn.clicked.connect(self._start_imaging)
        img_layout.addWidget(self._acquire_btn)

        # Imaging progress bar
        self._img_progress_bar = QProgressBar()
        self._img_progress_bar.setRange(0, 100)
        self._img_progress_bar.setValue(0)
        self._img_progress_bar.setVisible(False)
        self._img_progress_bar.setFixedHeight(8)
        self._img_progress_bar.setStyleSheet(
            "QProgressBar { background: #12181f; border: 1px solid #059669; border-radius: 4px; }"
            "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 #059669, stop:1 #38bdf8); border-radius: 4px; }"
        )
        img_layout.addWidget(self._img_progress_bar)

        self._img_status_label = QLabel("")
        self._img_status_label.setStyleSheet("color: #38bdf8; font-size: 10px; font-family: monospace;")
        self._img_status_label.setAlignment(Qt.AlignCenter)
        img_layout.addWidget(self._img_status_label)

        # Forensic Acquisition Console
        self._img_console = QTextBrowser()
        self._img_console.setFixedHeight(90)
        self._img_console.setStyleSheet(
            "QTextBrowser { background: #050b11; color: #34d399; font-family: 'Consolas', monospace; "
            "font-size: 10px; border: 1px solid #1e3a5f; border-radius: 4px; padding: 4px; }"
        )
        self._img_console.setText(
            "[READY] Forensic Acquisition Subsystem Standby.\n"
            "[INFO] Bit-stream imaging calculates SHA-256 + MD5 in real-time."
        )
        img_layout.addWidget(self._img_console)

        self._tab_widget.addTab(tab2_widget, "💾 Forensic Acquisition (.img)")
        form_layout.addWidget(self._tab_widget)
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

        splitter.setSizes([450, 610])

    def set_active_case(self, case_id: Optional[str]) -> None:
        """Called by MainWindow when the active case changes."""
        has_case = bool(case_id)
        self._no_case_panel.setVisible(not has_case)
        self._import_btn.setEnabled(has_case and self._selected_path is not None)
        self._acquire_btn.setEnabled(has_case and getattr(self, "_img_selected_path", None) is not None)
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
        self._acquire_btn.setEnabled(not no_case and getattr(self, "_img_selected_path", None) is not None)

    # ─── File selection (Tab 1) ───────────────────────────────────────────────

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
        display = str(p) if len(str(p)) < 80 else f"…{str(p)[-78:]}"
        self._file_path_label.setText(display)

        try:
            size = p.stat().st_size
            size_str = self._format_size_local(size)
        except OSError:
            size_str = "unknown size"
        self._file_info_label.setText(f"Extension: {p.suffix.lower()}  |  Size: {size_str}")
        self._import_btn.setEnabled(bool(self._main_window.active_case_id))

    # ─── Forensic Image selection (Tab 2) ─────────────────────────────────────

    def _browse_image_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Raw Storage Device / Disk Dump",
            "",
            "Forensic Raw Dumps (*.raw *.dd *.img *.bin);;All Files (*)",
        )
        if not path:
            return
        self._set_img_source(Path(path))

    def _load_demo_raw_dump(self) -> None:
        sample_path = Path(__file__).resolve().parent.parent.parent.parent / "sample_evidence" / "EX04_Damaged_DVR_Carve_Target.raw"
        if sample_path.exists():
            self._set_img_source(sample_path)
            self._img_description_input.setText("Seized damaged DVR drive containing wiped partition tables and embedded H.264 streams.")
        else:
            QMessageBox.information(self, "Sample Exhibit", f"Sample file not found at:\n{sample_path}")

    def _set_img_source(self, p: Path) -> None:
        self._img_selected_path = p
        display = str(p) if len(str(p)) < 80 else f"…{str(p)[-78:]}"
        self._img_path_label.setText(display)
        try:
            size = p.stat().st_size
            size_str = self._format_size_local(size)
        except OSError:
            size_str = "unknown size"
        self._img_info_label.setText(f"Source Type: Raw Bit-Stream  |  Size: {size_str}")
        self._acquire_btn.setEnabled(bool(self._main_window.active_case_id))
        self._img_console.append(f"[LOAD] Selected acquisition target: {p.name} ({size_str})")

    @staticmethod
    def _format_size_local(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # ─── Import workflow (Tab 1) ──────────────────────────────────────────────

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

        self._import_btn.setEnabled(False)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(True)
        self._status_label.setText("Starting import…")

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
        r: ImportResult = result
        self._progress_bar.setValue(100)
        self._status_label.setText(
            f"✔ Import complete — {r.evidence_number}  |  SHA-256: {r.original_sha256[:16]}…"
        )
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
        QMessageBox.critical(self, "Import Failed", f"Evidence import failed:\n\n{message}")

    # ─── Forensic Imaging workflow (Tab 2) ────────────────────────────────────

    def _start_imaging(self) -> None:
        case_id = self._main_window.active_case_id
        source_p = getattr(self, "_img_selected_path", None)
        if not case_id or not source_p:
            return

        examiner = self._img_investigator_input.text().strip()
        if not examiner:
            QMessageBox.warning(self, "Missing Information", "Please enter the forensic examiner's name.")
            return

        ev_number = self._img_ev_number_input.text().strip() or None
        description = self._img_description_input.toPlainText().strip() or None

        # Parse block size combo
        block_text = self._img_block_combo.currentText()
        if "128 KB" in block_text:
            block_size = 131072
        elif "512 KB" in block_text:
            block_size = 524288
        elif "4 KB" in block_text:
            block_size = 4096
        else:
            block_size = 65536

        simulated_wb = self._img_write_block_cb.isChecked()

        self._acquire_btn.setEnabled(False)
        self._img_progress_bar.setValue(0)
        self._img_progress_bar.setVisible(True)
        self._img_status_label.setText("Initializing bit-stream acquisition...")
        self._img_console.append(f"\n[START] Acquiring {source_p.name} (Block size: {block_size} bytes)...")
        self._img_console.append(f"[SECURITY] Write-block protection: {'SIMULATED' if simulated_wb else 'DIRECT HARDWARE'}")

        self._img_worker = ImagingWorker(
            case_id=case_id,
            source_path=source_p,
            investigator=examiner,
            evidence_number=ev_number,
            description=description,
            block_size=block_size,
            simulated_write_blocked=simulated_wb,
        )
        self._img_worker.progress.connect(self._on_img_progress)
        self._img_worker.finished.connect(self._on_img_finished)
        self._img_worker.failed.connect(self._on_img_failed)
        self._img_worker.start()

    def _on_img_progress(self, label: str, done: int, total: int) -> None:
        self._img_status_label.setText(label)
        if total > 0:
            pct = int(done * 100 / total)
            self._img_progress_bar.setValue(pct)

    def _on_img_finished(self, result: object) -> None:
        r: ImagingResult = result
        self._img_progress_bar.setValue(100)
        self._img_status_label.setText(
            f"✔ Acquired {r.evidence_number} (.img) | SHA-256: {r.sha256[:16]}… (MATCHED)"
        )
        self._img_console.append(f"[SUCCESS] Forensic image written: {r.image_path.name}")
        self._img_console.append(f"[CRYPTO] SHA-256: {r.sha256}")
        self._img_console.append(f"[CRYPTO] MD5:    {r.md5}")
        self._img_console.append(f"[VERIFY] Read-back integrity verification: PASSED")
        self._img_console.append(f"[CUSTODY] Logged IMAGE_CREATED and IMAGE_VERIFIED to hash ledger.")
        self._img_console.append(f"[MANIFEST] imaging_manifest.json sealed in vault.")

        self._img_selected_path = None
        self._img_path_label.setText("No raw device or dump selected")
        self._img_info_label.setText("")
        self._img_ev_number_input.clear()
        self._img_description_input.clear()
        self._acquire_btn.setEnabled(False)
        self.refresh()

        QMessageBox.information(
            self,
            "Forensic Acquisition Complete",
            f"Forensic bit-stream image successfully acquired!\n\n"
            f"Exhibit Number: {r.evidence_number}\n"
            f"Image File:     {r.image_path.name}\n"
            f"Size:           {self._format_size_local(r.file_size_bytes)}\n"
            f"SHA-256:        {r.sha256}\n"
            f"MD5:            {r.md5}\n\n"
            f"Verified working copy and atomic manifest have been generated.",
        )

    def _on_img_failed(self, message: str) -> None:
        self._img_progress_bar.setVisible(False)
        self._img_status_label.setText("Acquisition failed")
        self._img_console.append(f"[ERROR] {message}")
        case_id = self._main_window.active_case_id
        self._acquire_btn.setEnabled(bool(case_id) and getattr(self, "_img_selected_path", None) is not None)
        QMessageBox.critical(self, "Acquisition Failed", f"Forensic imaging failed:\n\n{message}")

