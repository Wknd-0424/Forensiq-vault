"""
forensiq/ui/pages/case_page.py
--------------------------------
Case Management page.

Features:
  - Create Case form (case number, title, description,
    authority/reference, investigator name)
  - Existing case list table
  - Select/open case (sets active case in main window)

Phase 1: Fully implemented.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from forensiq.ui.widgets.status_badge import StatusBadge
from forensiq.ui.widgets.warning_panel import WarningPanel
from forensiq.utils.utc_utils import to_iso8601


class CasePage(QWidget):
    """Case creation form and case browser."""

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._mw = main_window
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        vbox = QVBoxLayout(container)
        vbox.setContentsMargins(24, 24, 24, 24)
        vbox.setSpacing(20)

        # -- Page header --
        title = QLabel("Case Management")
        title.setObjectName("page_title")
        vbox.addWidget(title)
        subtitle = QLabel("Create and manage forensic cases.")
        subtitle.setObjectName("page_subtitle")
        vbox.addWidget(subtitle)

        # -- Create case form --
        form_group = QGroupBox("Create New Case")
        form_layout = QVBoxLayout(form_group)
        form_layout.setSpacing(10)

        # Case number
        form_layout.addWidget(self._field_label("Case Number *"))
        self._inp_case_number = QLineEdit()
        self._inp_case_number.setPlaceholderText("e.g. FIR-2026-001")
        form_layout.addWidget(self._inp_case_number)

        # Title
        form_layout.addWidget(self._field_label("Case Title *"))
        self._inp_title = QLineEdit()
        self._inp_title.setPlaceholderText("Brief descriptive title")
        form_layout.addWidget(self._inp_title)

        # Authority/reference
        form_layout.addWidget(self._field_label("Authority / Reference Number"))
        self._inp_authority = QLineEdit()
        self._inp_authority.setPlaceholderText("FIR number, warrant number, internal ref, etc.")
        form_layout.addWidget(self._inp_authority)

        # Description
        form_layout.addWidget(self._field_label("Case Description"))
        self._inp_description = QTextEdit()
        self._inp_description.setPlaceholderText("Optional: describe the case context.")
        self._inp_description.setFixedHeight(80)
        form_layout.addWidget(self._inp_description)

        # Investigator name
        form_layout.addWidget(self._field_label("Investigator Name *"))
        self._inp_investigator = QLineEdit()
        self._inp_investigator.setPlaceholderText("Full name of the investigating officer/analyst")
        form_layout.addWidget(self._inp_investigator)

        # Buttons
        btn_row = QHBoxLayout()
        self._btn_create = QPushButton("＋  Create Case")
        self._btn_create.setObjectName("primary_btn")
        self._btn_create.setFixedHeight(36)
        self._btn_create.clicked.connect(self._on_create_case)
        self._btn_clear = QPushButton("Clear Form")
        self._btn_clear.setFixedHeight(36)
        self._btn_clear.clicked.connect(self._clear_form)
        btn_row.addWidget(self._btn_create)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()
        form_layout.addLayout(btn_row)

        # Status message
        self._form_status = QLabel("")
        self._form_status.setObjectName("value_label")
        self._form_status.setWordWrap(True)
        form_layout.addWidget(self._form_status)

        vbox.addWidget(form_group)

        # -- Existing case list --
        list_group = QGroupBox("Existing Cases")
        list_layout = QVBoxLayout(list_group)

        list_hdr = QHBoxLayout()
        self._btn_refresh = QPushButton("↻  Refresh")
        self._btn_refresh.setFixedHeight(30)
        self._btn_refresh.clicked.connect(self._load_cases)
        self._btn_open_case = QPushButton("Open Selected Case →")
        self._btn_open_case.setObjectName("primary_btn")
        self._btn_open_case.setFixedHeight(30)
        self._btn_open_case.clicked.connect(self._on_open_case)
        list_hdr.addWidget(self._btn_refresh)
        list_hdr.addStretch()
        list_hdr.addWidget(self._btn_open_case)
        list_layout.addLayout(list_hdr)

        self._case_table = QTableWidget(0, 6)
        self._case_table.setHorizontalHeaderLabels(
            ["Case Number", "Title", "Investigator", "Status", "Created (UTC)", "ID"]
        )
        self._case_table.horizontalHeader().setStretchLastSection(True)
        self._case_table.setAlternatingRowColors(True)
        self._case_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._case_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._case_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._case_table.verticalHeader().setVisible(False)
        self._case_table.setMinimumHeight(200)
        self._case_table.setSortingEnabled(True)
        list_layout.addWidget(self._case_table)

        vbox.addWidget(list_group)
        vbox.addStretch()

    @staticmethod
    def _field_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("field_label")
        return lbl

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_create_case(self) -> None:
        from forensiq.database import session_scope
        from forensiq.services.case_service import CaseValidationError, create_case

        case_number = self._inp_case_number.text().strip()
        title = self._inp_title.text().strip()
        authority = self._inp_authority.text().strip()
        description = self._inp_description.toPlainText().strip()
        investigator = self._inp_investigator.text().strip()

        try:
            with session_scope() as session:
                case = create_case(
                    session=session,
                    case_number=case_number,
                    title=title,
                    investigator_name=investigator,
                    description=description or None,
                    authority_reference=authority or None,
                )
                case_id = case.id
                case_num = case.case_number

            self._form_status.setStyleSheet("color: #56d364;")
            self._form_status.setText(
                f"✔  Case '{case_num}' created successfully. ID: {case_id}"
            )
            self._clear_form()
            self._load_cases()

            # Auto-select the newly created case
            self._mw.set_active_case_id(case_id)

        except CaseValidationError as e:
            self._form_status.setStyleSheet("color: #f85149;")
            self._form_status.setText(f"✖  {e}")
        except Exception as e:
            self._form_status.setStyleSheet("color: #f85149;")
            self._form_status.setText(f"✖  Unexpected error: {e}")

    def _on_open_case(self) -> None:
        selected = self._case_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "No Selection", "Select a case from the list first.")
            return
        row = self._case_table.currentRow()
        case_id = self._case_table.item(row, 5).text()
        self._mw.set_active_case_id(case_id)
        QMessageBox.information(
            self, "Case Opened",
            f"Case {self._case_table.item(row, 0).text()} is now the active case."
        )

    def _clear_form(self) -> None:
        self._inp_case_number.clear()
        self._inp_title.clear()
        self._inp_authority.clear()
        self._inp_description.clear()
        self._inp_investigator.clear()
        self._form_status.setText("")

    def _load_cases(self) -> None:
        from forensiq.database import get_session
        from forensiq.services.case_service import list_cases

        session = get_session()
        try:
            cases = list_cases(session)
            self._case_table.setRowCount(len(cases))
            for row, case in enumerate(cases):
                data = [
                    case.case_number,
                    case.title,
                    case.created_by,
                    case.status,
                    to_iso8601(case.created_at_utc),
                    case.id,
                ]
                for col, text in enumerate(data):
                    item = QTableWidgetItem(str(text))
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    self._case_table.setItem(row, col, item)
            self._case_table.resizeColumnsToContents()
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Navigation hook
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Called every time this page is navigated to."""
        self._load_cases()
