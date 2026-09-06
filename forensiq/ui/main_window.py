"""
forensiq/ui/main_window.py
---------------------------
QMainWindow — application shell.

Layout:
  ┌─────────────────────────────────────────────────┐
  │  Header bar (app name | case | evidence | clock) │
  ├────────────┬────────────────────────────────────┤
  │  Sidebar   │  QStackedWidget (pages)            │
  │  nav btns  │                                    │
  └────────────┴────────────────────────────────────┘

Navigation:
  Each sidebar button maps to a page index in the QStackedWidget.
  Pages implement a refresh() method called on every navigation.

Active case state:
  main_window.set_active_case_id(case_id) updates the header and
  makes the case available to all pages via main_window.active_case_id.

Phase 1: Fully implemented.
"""

import logging
from typing import Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from forensiq.config import APP_NAME, APP_VERSION
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """
    Application main window with sidebar navigation, header bar,
    UTC live clock, and a QStackedWidget page area.
    """

    # Navigation entries: (button_label, page_key, tooltip)
    _NAV_ITEMS = [
        ("🏠  Dashboard",          "dashboard",             "Overview and quick actions"),
        ("📁  Case Management",    "case",                  "Create and manage cases"),
        ("📥  Evidence Import",    "evidence_import",       "Import controlled evidence files"),
        ("🔍  Evidence Details",   "evidence_detail",       "Evidence integrity and hashes"),
        ("🎬  Video & Metadata",   "video_metadata",        "ffprobe metadata and adapter result"),
        ("📅  Timeline & AI",      "timeline_ai",           "Timeline, timestamp and AI triage"),
        ("⛓  Chain of Custody",   "custody_report",        "Custody ledger and report generation"),
        ("🔌  Adapter Matrix",     "adapter_capabilities",  "Vendor adapter capability matrix"),
    ]

    def __init__(self):
        super().__init__()
        self._active_case_id: Optional[str] = None
        self._active_case_number: Optional[str] = None
        self._active_evidence_id: Optional[str] = None
        self._nav_buttons: dict[str, QPushButton] = {}
        self._pages: dict[str, QWidget] = {}

        self._build_ui()
        self._start_clock()
        logger.info("MainWindow initialised.")

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def active_case_id(self) -> Optional[str]:
        return self._active_case_id

    @property
    def active_evidence_id(self) -> Optional[str]:
        return self._active_evidence_id

    def update_chain_status(self, status: Optional[str]) -> None:
        """Update the header bar cryptographic chain integrity indicator."""
        if status in ("VALID", "INTACT"):
            self._header_integrity.setText("● Chain: INTACT")
            self._header_integrity.setStyleSheet("color: #34d399; font-weight: bold;")
        elif status in ("COMPROMISED", "MISMATCH") or (status and "INVALID" in status):
            self._header_integrity.setText("● Chain: COMPROMISED")
            self._header_integrity.setStyleSheet("color: #f87171; font-weight: bold;")
        elif status in ("EMPTY_CHAIN", "EMPTY"):
            self._header_integrity.setText("● Chain: EMPTY")
            self._header_integrity.setStyleSheet("color: #9aa5b4;")
        else:
            self._header_integrity.setText("● Chain: —")
            self._header_integrity.setStyleSheet("color: #9aa5b4;")

    def set_active_case_id(self, case_id: str) -> None:
        """Set the currently active case and update the header."""
        from forensiq.database import get_session
        from forensiq.services.case_service import get_case
        from forensiq.services.custody_service import verify_chain
        session = get_session()
        try:
            case = get_case(session, case_id)
            if case:
                self._active_case_id = case.id
                self._active_case_number = case.case_number
                self._header_case_value.setText(
                    f"{case.case_number} — {case.title[:40]}"
                )
                self._active_evidence_id = None
                self._header_evidence_value.setText("—")
                
                # Check chain status for header indicator
                res, _ = verify_chain(session, case.id)
                self.update_chain_status(res.value)

                logger.info("Active case set: %s (%s)", case.case_number, case.id)
        finally:
            session.close()

    def set_active_evidence_id(self, evidence_id: str) -> None:
        """Set the currently active evidence item and update the header."""
        from forensiq.database import get_session
        from forensiq.models.evidence import EvidenceItem
        session = get_session()
        try:
            ev = session.query(EvidenceItem).filter(
                EvidenceItem.id == evidence_id
            ).first()
            if ev:
                self._active_evidence_id = ev.id
                self._header_evidence_value.setText(ev.evidence_number)
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def navigate_to(self, page_key: str) -> None:
        """Switch the stacked widget to *page_key* and call its refresh()."""
        if page_key not in self._pages:
            logger.warning("navigate_to: unknown page key '%s'", page_key)
            return

        # Update sidebar button checked state
        for key, btn in self._nav_buttons.items():
            btn.setChecked(key == page_key)

        # Switch page
        widget = self._pages[page_key]
        self._stack.setCurrentWidget(widget)

        # Call refresh if implemented
        if hasattr(widget, "refresh"):
            try:
                widget.refresh()
            except Exception as exc:
                logger.exception("Error refreshing page '%s': %s", page_key, exc)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — SIH 2026")
        self.setMinimumSize(1280, 760)
        self.resize(1920, 930)

        # Central widget holds: header + (sidebar | content)
        central = QWidget()
        self.setCentralWidget(central)
        root_vbox = QVBoxLayout(central)
        root_vbox.setContentsMargins(0, 0, 0, 0)
        root_vbox.setSpacing(0)

        # -- Header bar --
        root_vbox.addWidget(self._build_header())

        # -- Body (sidebar + content) --
        body = QWidget()
        body_hbox = QHBoxLayout(body)
        body_hbox.setContentsMargins(0, 0, 0, 0)
        body_hbox.setSpacing(0)
        body_hbox.addWidget(self._build_sidebar())
        body_hbox.addWidget(self._build_content_area(), stretch=1)
        root_vbox.addWidget(body, stretch=1)

        # Navigate to dashboard on startup
        self.navigate_to("dashboard")

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("header_bar")
        bar.setFixedHeight(48)
        hbox = QHBoxLayout(bar)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(0)

        # App name
        app_name_lbl = QLabel(f"⚖  {APP_NAME}")
        app_name_lbl.setObjectName("header_app_name")
        app_name_lbl.setFixedWidth(220)
        app_name_lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        hbox.addWidget(app_name_lbl)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.VLine)
        sep1.setFixedWidth(1)
        hbox.addWidget(sep1)

        # Case info
        case_section = QWidget()
        case_hbox = QHBoxLayout(case_section)
        case_hbox.setContentsMargins(16, 0, 16, 0)
        case_hbox.setSpacing(6)
        case_lbl = QLabel("Case:")
        case_lbl.setObjectName("header_case_label")
        self._header_case_value = QLabel("No case open")
        self._header_case_value.setObjectName("header_case_value")
        case_hbox.addWidget(case_lbl)
        case_hbox.addWidget(self._header_case_value)
        hbox.addWidget(case_section)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setFixedWidth(1)
        hbox.addWidget(sep2)

        # Evidence info
        ev_section = QWidget()
        ev_hbox = QHBoxLayout(ev_section)
        ev_hbox.setContentsMargins(16, 0, 16, 0)
        ev_hbox.setSpacing(6)
        ev_lbl = QLabel("Evidence:")
        ev_lbl.setObjectName("header_case_label")
        self._header_evidence_value = QLabel("—")
        self._header_evidence_value.setObjectName("header_case_value")
        ev_hbox.addWidget(ev_lbl)
        ev_hbox.addWidget(self._header_evidence_value)
        hbox.addWidget(ev_section)

        hbox.addStretch()

        # Integrity indicator
        self._header_integrity = QLabel("● Chain: —")
        self._header_integrity.setObjectName("header_case_label")
        self._header_integrity.setContentsMargins(0, 0, 8, 0)
        hbox.addWidget(self._header_integrity)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.Shape.VLine)
        sep3.setFixedWidth(1)
        hbox.addWidget(sep3)

        # UTC clock
        self._clock_label = QLabel("UTC: ——————————")
        self._clock_label.setObjectName("header_clock")
        self._clock_label.setFixedWidth(210)
        self._clock_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        hbox.addWidget(self._clock_label)

        return bar

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        vbox = QVBoxLayout(sidebar)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        # Sidebar title block
        title_block = QWidget()
        title_vbox = QVBoxLayout(title_block)
        title_vbox.setContentsMargins(16, 20, 16, 8)
        title_vbox.setSpacing(2)
        title_lbl = QLabel("FORENSIQ VAULT")
        title_lbl.setObjectName("sidebar_title")
        subtitle_lbl = QLabel("SIH 2026 · Problem 26150")
        subtitle_lbl.setObjectName("sidebar_subtitle")
        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(subtitle_lbl)
        vbox.addWidget(title_block)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        vbox.addWidget(sep)

        # Nav buttons
        for label, key, tooltip in self._NAV_ITEMS:
            btn = QPushButton(label)
            btn.setObjectName("nav_btn")
            btn.setCheckable(True)
            btn.setToolTip(tooltip)
            btn.setFixedHeight(40)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.clicked.connect(lambda checked=False, k=key: self.navigate_to(k))
            self._nav_buttons[key] = btn
            vbox.addWidget(btn)

        vbox.addStretch()

        # Bottom version label
        ver_lbl = QLabel(f"v{APP_VERSION} · Prototype")
        ver_lbl.setObjectName("sidebar_subtitle")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(ver_lbl)

        return sidebar

    def _build_content_area(self) -> QWidget:
        wrapper = QWidget()
        wrapper.setObjectName("content_area")
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._stack = QStackedWidget()
        layout.addWidget(self._stack)

        # Import and instantiate all pages
        from forensiq.ui.pages.dashboard_page import DashboardPage
        from forensiq.ui.pages.case_page import CasePage
        from forensiq.ui.pages.evidence_import_page import EvidenceImportPage
        from forensiq.ui.pages.evidence_detail_page import EvidenceDetailPage
        from forensiq.ui.pages.video_metadata_page import VideoMetadataPage
        from forensiq.ui.pages.timeline_ai_page import TimelineAIPage
        from forensiq.ui.pages.custody_report_page import CustodyReportPage
        from forensiq.ui.pages.adapter_capabilities_page import AdapterCapabilitiesPage

        page_classes = {
            "dashboard":             DashboardPage,
            "case":                  CasePage,
            "evidence_import":       EvidenceImportPage,
            "evidence_detail":       EvidenceDetailPage,
            "video_metadata":        VideoMetadataPage,
            "timeline_ai":           TimelineAIPage,
            "custody_report":        CustodyReportPage,
            "adapter_capabilities":  AdapterCapabilitiesPage,
        }

        for key, cls in page_classes.items():
            page = cls(main_window=self)
            self._pages[key] = page
            self._stack.addWidget(page)

        return wrapper

    # ------------------------------------------------------------------
    # UTC clock
    # ------------------------------------------------------------------

    def _start_clock(self) -> None:
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)
        self._update_clock()

    def _update_clock(self) -> None:
        ts = to_iso8601(now_utc())
        self._clock_label.setText(f"UTC  {ts}")
