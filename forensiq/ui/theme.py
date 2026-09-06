"""
forensiq/ui/theme.py
---------------------
Dark forensic theme — Qt Style Sheet (QSS).

Colour palette:
  Background:     #0d1117  (near-black)
  Panel:          #161b22  (dark navy)
  Surface:        #21262d  (card/input background)
  Border:         #30363d
  Text primary:   #c9d1d9
  Text secondary: #8b949e
  Accent blue:    #388bfd  (integrity / confirmed)
  Accent green:   #56d364  (verified / valid)
  Accent amber:   #d29922  (warning / pending)
  Accent red:     #f85149  (error / invalid)
  Sidebar:        #0d1117
"""

PALETTE = {
    "bg":          "#0d1117",
    "panel":       "#161b22",
    "surface":     "#21262d",
    "border":      "#30363d",
    "text":        "#c9d1d9",
    "text_muted":  "#8b949e",
    "accent":      "#388bfd",
    "green":       "#56d364",
    "amber":       "#d29922",
    "red":         "#f85149",
    "sidebar":     "#0d1117",
}

STYLESHEET = f"""
/* ===== Global ===== */
QMainWindow, QWidget {{
    background-color: {PALETTE['bg']};
    color: {PALETTE['text']};
    font-family: "Segoe UI", "Inter", "SF Pro Text", "Ubuntu", sans-serif;
    font-size: 13px;
}}

/* ===== Sidebar ===== */
#sidebar {{
    background-color: {PALETTE['sidebar']};
    border-right: 1px solid {PALETTE['border']};
    min-width: 220px;
    max-width: 220px;
}}

#sidebar_title {{
    color: {PALETTE['accent']};
    font-size: 15px;
    font-weight: bold;
    padding: 20px 16px 8px 16px;
    letter-spacing: 1px;
}}

#sidebar_subtitle {{
    color: {PALETTE['text_muted']};
    font-size: 10px;
    padding: 0px 16px 16px 16px;
}}

QPushButton#nav_btn {{
    background-color: transparent;
    color: {PALETTE['text_muted']};
    border: none;
    border-radius: 6px;
    text-align: left;
    padding: 10px 16px;
    font-size: 13px;
    margin: 1px 8px;
}}

QPushButton#nav_btn:hover {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
}}

QPushButton#nav_btn:checked, QPushButton#nav_btn:pressed {{
    background-color: {PALETTE['accent']};
    color: white;
    font-weight: bold;
}}

/* ===== Header bar ===== */
#header_bar {{
    background-color: {PALETTE['panel']};
    border-bottom: 1px solid {PALETTE['border']};
    min-height: 48px;
    max-height: 48px;
}}

#header_app_name {{
    color: {PALETTE['accent']};
    font-size: 14px;
    font-weight: bold;
    padding-left: 16px;
}}

#header_case_label {{
    color: {PALETTE['text_muted']};
    font-size: 12px;
}}

#header_case_value {{
    color: {PALETTE['text']};
    font-size: 12px;
    font-weight: bold;
}}

#header_clock {{
    color: {PALETTE['text_muted']};
    font-size: 11px;
    padding-right: 16px;
    font-family: "Consolas", "Courier New", monospace;
}}

/* ===== Content area ===== */
#content_area {{
    background-color: {PALETTE['bg']};
    padding: 0px;
}}

/* ===== Page titles ===== */
QLabel#page_title {{
    color: {PALETTE['text']};
    font-size: 20px;
    font-weight: bold;
    padding: 24px 24px 8px 24px;
}}

QLabel#page_subtitle {{
    color: {PALETTE['text_muted']};
    font-size: 12px;
    padding: 0px 24px 16px 24px;
}}

/* ===== Stat cards (dashboard) ===== */
QFrame#stat_card {{
    background-color: {PALETTE['panel']};
    border: 1px solid {PALETTE['border']};
    border-radius: 8px;
}}

QLabel#stat_number {{
    color: {PALETTE['accent']};
    font-size: 32px;
    font-weight: bold;
}}

QLabel#stat_label {{
    color: {PALETTE['text_muted']};
    font-size: 12px;
}}

/* ===== Buttons ===== */
QPushButton {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
}}

QPushButton:hover {{
    background-color: {PALETTE['accent']};
    color: white;
    border-color: {PALETTE['accent']};
}}

QPushButton:pressed {{
    background-color: #1a6fd4;
}}

QPushButton:disabled {{
    color: {PALETTE['text_muted']};
    background-color: {PALETTE['panel']};
    border-color: {PALETTE['border']};
}}

QPushButton#primary_btn {{
    background-color: {PALETTE['accent']};
    color: white;
    border: none;
    font-weight: bold;
    padding: 8px 20px;
}}

QPushButton#primary_btn:hover {{
    background-color: #1a6fd4;
}}

QPushButton#danger_btn {{
    background-color: transparent;
    color: {PALETTE['red']};
    border: 1px solid {PALETTE['red']};
}}

QPushButton#danger_btn:hover {{
    background-color: {PALETTE['red']};
    color: white;
}}

/* ===== Input fields ===== */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {PALETTE['accent']};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {PALETTE['accent']};
}}

QLineEdit:read-only {{
    color: {PALETTE['text_muted']};
    background-color: {PALETTE['panel']};
}}

/* ===== Labels ===== */
QLabel#field_label {{
    color: {PALETTE['text_muted']};
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QLabel#value_label {{
    color: {PALETTE['text']};
}}

QLabel#hash_value {{
    color: {PALETTE['green']};
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}}

/* ===== Tables ===== */
QTableWidget, QTableView {{
    background-color: {PALETTE['panel']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    gridline-color: {PALETTE['border']};
    alternate-background-color: {PALETTE['surface']};
    selection-background-color: {PALETTE['accent']};
    selection-color: white;
}}

QTableWidget::item, QTableView::item {{
    padding: 6px 8px;
}}

QHeaderView::section {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text_muted']};
    border: none;
    border-bottom: 1px solid {PALETTE['border']};
    border-right: 1px solid {PALETTE['border']};
    padding: 8px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
}}

/* ===== Scroll bars ===== */
QScrollBar:vertical {{
    background: {PALETTE['panel']};
    width: 8px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical {{
    background: {PALETTE['border']};
    border-radius: 4px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background: {PALETTE['text_muted']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {PALETTE['panel']};
    height: 8px;
    border-radius: 4px;
}}

QScrollBar::handle:horizontal {{
    background: {PALETTE['border']};
    border-radius: 4px;
    min-width: 20px;
}}

/* ===== ComboBox ===== */
QComboBox {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    padding: 6px 10px;
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}

QComboBox QAbstractItemView {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    selection-background-color: {PALETTE['accent']};
    border: 1px solid {PALETTE['border']};
}}

/* ===== Group boxes ===== */
QGroupBox {{
    color: {PALETTE['text_muted']};
    border: 1px solid {PALETTE['border']};
    border-radius: 6px;
    margin-top: 12px;
    padding: 12px 8px 8px 8px;
    font-size: 11px;
    font-weight: bold;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: {PALETTE['text_muted']};
}}

/* ===== Tabs ===== */
QTabWidget::pane {{
    border: 1px solid {PALETTE['border']};
    background-color: {PALETTE['panel']};
    border-radius: 0px 6px 6px 6px;
}}

QTabBar::tab {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text_muted']};
    border: 1px solid {PALETTE['border']};
    padding: 8px 16px;
    margin-right: 2px;
    border-bottom: none;
    border-radius: 6px 6px 0px 0px;
}}

QTabBar::tab:selected {{
    background-color: {PALETTE['panel']};
    color: {PALETTE['text']};
    border-bottom: 2px solid {PALETTE['accent']};
}}

/* ===== Warning / disclaimer panels ===== */
QFrame#warning_panel {{
    background-color: #261d00;
    border: 1px solid {PALETTE['amber']};
    border-radius: 6px;
    padding: 4px;
}}

QFrame#error_panel {{
    background-color: #220000;
    border: 1px solid {PALETTE['red']};
    border-radius: 6px;
    padding: 4px;
}}

QFrame#info_panel {{
    background-color: #001b33;
    border: 1px solid {PALETTE['accent']};
    border-radius: 6px;
    padding: 4px;
}}

QLabel#warning_text {{
    color: {PALETTE['amber']};
    font-size: 12px;
    padding: 8px;
}}

QLabel#error_text {{
    color: {PALETTE['red']};
    font-size: 12px;
    padding: 8px;
}}

QLabel#info_text {{
    color: {PALETTE['accent']};
    font-size: 12px;
    padding: 8px;
}}

/* ===== Status badges ===== */
QLabel#badge_verified {{
    color: white;
    background-color: {PALETTE['green']};
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: bold;
}}

QLabel#badge_pending {{
    color: white;
    background-color: {PALETTE['amber']};
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: bold;
}}

QLabel#badge_error {{
    color: white;
    background-color: {PALETTE['red']};
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: bold;
}}

QLabel#badge_experimental {{
    color: {PALETTE['bg']};
    background-color: {PALETTE['amber']};
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: bold;
}}

QLabel#badge_placeholder {{
    color: {PALETTE['text_muted']};
    background-color: {PALETTE['surface']};
    border: 1px solid {PALETTE['border']};
    border-radius: 10px;
    padding: 2px 10px;
    font-size: 11px;
}}

/* ===== Separator ===== */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {PALETTE['border']};
    background-color: {PALETTE['border']};
}}

/* ===== Splitter ===== */
QSplitter::handle {{
    background-color: {PALETTE['border']};
}}

/* ===== Progress bar ===== */
QProgressBar {{
    background-color: {PALETTE['surface']};
    border: 1px solid {PALETTE['border']};
    border-radius: 4px;
    text-align: center;
    color: {PALETTE['text']};
    height: 16px;
}}

QProgressBar::chunk {{
    background-color: {PALETTE['accent']};
    border-radius: 3px;
}}

/* ===== Message boxes ===== */
QMessageBox {{
    background-color: {PALETTE['panel']};
    color: {PALETTE['text']};
}}

QMessageBox QPushButton {{
    min-width: 80px;
}}

/* ===== Tooltips ===== */
QToolTip {{
    background-color: {PALETTE['surface']};
    color: {PALETTE['text']};
    border: 1px solid {PALETTE['border']};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


def apply_theme(app) -> None:
    """Apply the dark forensic theme to a QApplication instance."""
    app.setStyleSheet(STYLESHEET)
