"""
ForensIQ Vault — Multi-Vendor DVR/NVR Forensic Analysis Tool
SIH 2026 | Problem ID 26150 | NTRO | Theme: Blockchain & Cybersecurity

DISCLAIMER:
This is a student prototype for demonstration purposes.
It does not support every DVR/NVR vendor or proprietary format.
AI outputs are triage aids. Human review is required.
A matching hash verifies byte-level equality of compared files;
it does not independently establish original-world authenticity,
completeness, correct timestamps, or legal admissibility.
"""

import sys
from pathlib import Path

# Automatically attach workspace .venv site-packages if running via global Python
_venv_site = Path(__file__).resolve().parent.parent / ".venv" / "Lib" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

__version__ = "0.1.0"
__app_name__ = "ForensIQ Vault"
__tool_version__ = f"{__app_name__} v{__version__}"
