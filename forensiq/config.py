"""
forensiq/config.py
------------------
Application-wide configuration resolved from environment variables and
project-relative paths.  No secrets are stored here; use .env for overrides.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (silently ignored if missing)
_project_root = Path(__file__).parent.parent
load_dotenv(_project_root / ".env", override=False)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = _project_root

# Vault root: configurable via VAULT_ROOT env var; defaults to project/vault
_vault_env = os.getenv("VAULT_ROOT", "").strip()
VAULT_ROOT: Path = Path(_vault_env) if _vault_env else PROJECT_ROOT / "vault"

VAULT_ORIGINALS: Path = VAULT_ROOT / "originals"
VAULT_WORKING: Path = VAULT_ROOT / "working"
VAULT_DERIVATIVES: Path = VAULT_ROOT / "derivatives"
VAULT_MANIFESTS: Path = VAULT_ROOT / "manifests"
VAULT_REPORTS: Path = VAULT_ROOT / "reports"

# Database
DB_PATH: Path = PROJECT_ROOT / "forensiq.db"
DB_URL: str = f"sqlite:///{DB_PATH}"

# Templates
TEMPLATES_DIR: Path = PROJECT_ROOT / "forensiq" / "templates"

# ---------------------------------------------------------------------------
# External tools
# ---------------------------------------------------------------------------

# ffprobe: search PATH by default; override with FFPROBE_PATH
FFPROBE_PATH: str = os.getenv("FFPROBE_PATH", "ffprobe").strip() or "ffprobe"

# YOLO model: path to weights (.pt file)
_candidate_yolo = PROJECT_ROOT / "forensiq" / "ml" / "models" / "yolov8n.pt"
if not _candidate_yolo.exists():
    _candidate_yolo = PROJECT_ROOT / "yolov8n.pt"

YOLO_MODEL_PATH: str = os.getenv(
    "YOLO_MODEL_PATH",
    str(_candidate_yolo) if _candidate_yolo.exists() else "",
).strip()

# ---------------------------------------------------------------------------
# Evidence limits
# ---------------------------------------------------------------------------

MAX_EVIDENCE_SIZE_BYTES: int = int(
    os.getenv("MAX_EVIDENCE_SIZE_BYTES", str(2 * 1024 * 1024 * 1024))
)
# Alias used by file_utils.py (clearer name)
MAX_EVIDENCE_FILE_SIZE_BYTES: int = MAX_EVIDENCE_SIZE_BYTES

# Allowed import extensions (lowercase, including leading dot)
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".mp4", ".avi", ".mkv", ".mov", ".ts", ".m4v",
    ".dav", ".h264", ".h265", ".hkv",
    ".raw", ".dd", ".img", ".bin",
})


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

# 1 MiB chunk for streaming hash computation
HASH_CHUNK_SIZE: int = 1024 * 1024

# ---------------------------------------------------------------------------
# Application identity
# ---------------------------------------------------------------------------

APP_NAME: str = "ForensIQ Vault"
APP_VERSION: str = "0.1.0"
TOOL_VERSION: str = f"{APP_NAME} v{APP_VERSION}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LEVEL: str = os.getenv("APP_LOG_LEVEL", "INFO").upper()


def configure_logging() -> None:
    """Set up root logger.  Call once from main.py before anything else."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    # Silence noisy third-party loggers
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)


def ensure_vault_dirs() -> None:
    """Create vault directory tree if it does not exist.  Idempotent."""
    for vault_dir in (
        VAULT_ORIGINALS,
        VAULT_WORKING,
        VAULT_DERIVATIVES,
        VAULT_MANIFESTS,
        VAULT_REPORTS,
    ):
        vault_dir.mkdir(parents=True, exist_ok=True)
    logger.debug("Vault directories verified at: %s", VAULT_ROOT)
