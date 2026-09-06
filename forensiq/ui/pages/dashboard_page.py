"""
forensiq/ui/pages/dashboard_page.py
-------------------------------------
Dashboard page — first page shown after application launch.

Displays:
  - Total/active/closed case counts
  - Total evidence item count
  - Pending AI review count
  - Recent custody events (last 5)
  - Quick-action buttons

Phase 1: Fully implemented.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from forensiq.ui.widgets.warning_panel import InfoPanel
from forensiq.utils.utc_utils import to_iso8601


def _make_stat_card(number: str, label: str) -> QFrame:
    card = QFrame()
    card.setObjectName("stat_card")
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    vbox = QVBoxLayout(card)
    vbox.setContentsMargins(20, 20, 20, 20)
    vbox.setSpacing(4)
    num_lbl = QLabel(number)
    num_lbl.setObjectName("stat_number")
    num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    txt_lbl = QLabel(label)
    txt_lbl.setObjectName("stat_label")
    txt_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    vbox.addWidget(num_lbl)
    vbox.addWidget(txt_lbl)
    return card


class DashboardPage(QWidget):
    """
    Main dashboard page.
    Refreshed every time the user navigates here via refresh().
    """

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
        title = QLabel("Dashboard")
        title.setObjectName("page_title")
        title.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(title)

        subtitle = QLabel("ForensIQ Vault — Forensic Evidence Workflow Overview")
        subtitle.setObjectName("page_subtitle")
        subtitle.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(subtitle)

        # -- Info panel --
        vbox.addWidget(InfoPanel(
            "Import only legally obtained and authorised evidence. "
            "This tool is a student prototype for SIH 2026 demonstration. "
            "It is not a certified forensic tool."
        ))

        # -- Stat cards --
        self._stat_total_cases = _make_stat_card("—", "Total Cases")
        self._stat_active_cases = _make_stat_card("—", "Active Cases")
        self._stat_evidence = _make_stat_card("—", "Evidence Items")
        self._stat_pending_ai = _make_stat_card("—", "Pending AI Review")

        stat_grid = QGridLayout()
        stat_grid.setSpacing(12)
        stat_grid.addWidget(self._stat_total_cases,  0, 0)
        stat_grid.addWidget(self._stat_active_cases, 0, 1)
        stat_grid.addWidget(self._stat_evidence,     0, 2)
        stat_grid.addWidget(self._stat_pending_ai,   0, 3)
        vbox.addLayout(stat_grid)

        # -- Quick actions --
        actions_label = QLabel("Quick Actions")
        actions_label.setObjectName("field_label")
        vbox.addWidget(actions_label)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self._btn_new_case = QPushButton("＋  Create New Case")
        self._btn_new_case.setObjectName("primary_btn")
        self._btn_new_case.setFixedHeight(38)
        self._btn_new_case.clicked.connect(
            lambda: self._mw.navigate_to("case")
        )

        self._btn_import = QPushButton("📥  Import Evidence")
        self._btn_import.setFixedHeight(38)
        self._btn_import.clicked.connect(
            lambda: self._mw.navigate_to("evidence_import")
        )

        self._btn_open = QPushButton("🔍  Open Evidence")
        self._btn_open.setFixedHeight(38)
        self._btn_open.clicked.connect(
            lambda: self._mw.navigate_to("evidence_detail")
        )

        self._btn_adapter_matrix = QPushButton("🔌  Adapter Matrix")
        self._btn_adapter_matrix.setFixedHeight(38)
        self._btn_adapter_matrix.clicked.connect(
            lambda: self._mw.navigate_to("adapter_capabilities")
        )

        btn_row.addWidget(self._btn_new_case)
        btn_row.addWidget(self._btn_import)
        btn_row.addWidget(self._btn_open)
        btn_row.addWidget(self._btn_adapter_matrix)
        btn_row.addStretch()
        vbox.addLayout(btn_row)

        # -- Recent custody events --
        events_label = QLabel("Recent Custody Events")
        events_label.setObjectName("field_label")
        vbox.addWidget(events_label)

        self._events_table = QTableWidget(0, 4)
        self._events_table.setHorizontalHeaderLabels(
            ["Timestamp (UTC)", "Case", "Action", "Actor"]
        )
        self._events_table.horizontalHeader().setStretchLastSection(True)
        self._events_table.setAlternatingRowColors(True)
        self._events_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._events_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._events_table.verticalHeader().setVisible(False)
        self._events_table.setMinimumHeight(160)
        vbox.addWidget(self._events_table)

        vbox.addStretch()

    # ------------------------------------------------------------------
    # Data refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Re-query the database and update all dashboard widgets."""
        from forensiq.database import get_session
        from forensiq.models.custody import CustodyEvent
        from forensiq.models.evidence import EvidenceItem
        from forensiq.models.detection import AIDetection
        from forensiq.services.case_service import get_case_stats
        from forensiq.constants import ReviewerStatus

        session = get_session()
        try:
            stats = get_case_stats(session)
            evidence_count = session.query(EvidenceItem).count()
            pending_ai = (
                session.query(AIDetection)
                .filter(AIDetection.reviewer_status == ReviewerStatus.PENDING)
                .count()
            )

            # Update stat cards
            def _update_card(card: QFrame, value: str) -> None:
                lbl = card.findChild(QLabel, "stat_number")
                if lbl:
                    lbl.setObjectName("stat_number")
                    lbl.setText(value)

            # Find and update the number labels inside each card
            self._stat_total_cases.findChildren(QLabel)[0].setText(str(stats["total"]))
            self._stat_active_cases.findChildren(QLabel)[0].setText(str(stats["active"]))
            self._stat_evidence.findChildren(QLabel)[0].setText(str(evidence_count))
            self._stat_pending_ai.findChildren(QLabel)[0].setText(str(pending_ai))

            # Load recent custody events (last 5)
            recent = (
                session.query(CustodyEvent)
                .order_by(CustodyEvent.action_timestamp_utc.desc())
                .limit(5)
                .all()
            )

            self._events_table.setRowCount(len(recent))
            for row, ev in enumerate(recent):
                ts = to_iso8601(ev.action_timestamp_utc)
                case_id_short = ev.case_id[:8] + "…"
                actor = ev.actor_id or "—"

                for col, text in enumerate([ts, case_id_short, ev.action, actor]):
                    item = QTableWidgetItem(text)
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    self._events_table.setItem(row, col, item)

        finally:
            session.close()
