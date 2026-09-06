"""
forensiq/main.py
-----------------
Application entry point.

Run with:
    python -m forensiq

Startup sequence:
  1. Configure logging
  2. Ensure vault directories exist
  3. Initialise SQLite database (create_all)
  4. Launch PySide6 application
"""

import logging
import sys

from forensiq.config import APP_NAME, APP_VERSION, configure_logging, ensure_vault_dirs
from forensiq.database import init_db

logger = logging.getLogger(__name__)


def main() -> int:
    """
    Application entry point.
    Returns an exit code (0 = success).
    """
    # --- Logging ---
    configure_logging()
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)

    # --- Vault directories ---
    try:
        ensure_vault_dirs()
    except OSError as e:
        logger.critical("Cannot create vault directories: %s", e)
        print(f"ERROR: Cannot create vault directories: {e}", file=sys.stderr)
        return 1

    # --- Database ---
    try:
        init_db()
        from forensiq.database import session_scope
        from forensiq.adapters.registry import sync_adapter_profiles
        with session_scope() as session:
            sync_adapter_profiles(session)
    except Exception as e:
        logger.critical("Database initialisation failed: %s", e)
        print(f"ERROR: Database initialisation failed: {e}", file=sys.stderr)
        return 1

    # --- PySide6 application ---
    # Import Qt only after confirming DB is ready
    from PySide6.QtWidgets import QApplication
    from forensiq.ui.theme import apply_theme
    from forensiq.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("SIH 2026 — NTRO")

    apply_theme(app)

    window = MainWindow()
    window.show()

    logger.info("Application window displayed.")
    exit_code = app.exec()
    logger.info("Application exited with code %d.", exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
