"""
forensiq/utils/file_utils.py
-----------------------------
Safe filename and file validation for evidence import.

Phase 2: Fully implemented.
"""

import re
from pathlib import Path

from forensiq.config import ALLOWED_EXTENSIONS, MAX_EVIDENCE_FILE_SIZE_BYTES

# Disallowed characters on Windows (and generally unsafe on Linux)
_UNSAFE_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# Filenames that are reserved on Windows
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


class FileValidationError(ValueError):
    """Raised when a selected file fails evidence import validation."""


def validate_evidence_file(path: Path) -> None:
    """
    Validate a file for evidence import.  Raises FileValidationError on any failure.

    Checks (in order):
    1. Path exists and is a regular file (not a symlink, not a directory).
    2. Filename contains only safe characters.
    3. Filename is not a Windows reserved name.
    4. Extension is in the allowed whitelist.
    5. File size is within MAX_EVIDENCE_FILE_SIZE_BYTES.
    6. File size is > 0.

    Raises:
        FileValidationError with a user-readable message.
    """
    path = Path(path).resolve()

    # 1. Existence and type
    if not path.exists():
        raise FileValidationError(f"File does not exist: '{path.name}'")
    if path.is_symlink():
        raise FileValidationError(
            f"Symbolic links are not accepted as evidence: '{path.name}'"
        )
    if not path.is_file():
        raise FileValidationError(f"Path is not a regular file: '{path.name}'")

    filename = path.name

    # 2. Safe characters
    if _UNSAFE_CHARS_RE.search(filename):
        raise FileValidationError(
            f"Filename contains unsafe characters: '{filename}'"
        )

    # 3. Windows reserved names
    stem = path.stem.upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise FileValidationError(
            f"Filename is a reserved Windows name: '{filename}'"
        )

    # 4. Extension whitelist
    ext = path.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise FileValidationError(
            f"Extension '{ext}' is not in the allowed list.\n"
            f"Allowed: {allowed}"
        )

    # 5. Size upper bound
    try:
        size = path.stat().st_size
    except OSError as e:
        raise FileValidationError(f"Cannot determine file size: {e}") from e

    if size > MAX_EVIDENCE_FILE_SIZE_BYTES:
        limit_gb = MAX_EVIDENCE_FILE_SIZE_BYTES / (1024 ** 3)
        actual_mb = size / (1024 ** 2)
        raise FileValidationError(
            f"File is too large ({actual_mb:.1f} MB). "
            f"Maximum allowed: {limit_gb:.0f} GB."
        )

    # 6. Non-empty
    if size == 0:
        raise FileValidationError(f"File is empty: '{filename}'")


def is_safe_extension(filename: str) -> bool:
    """Return True if the extension is in the allowed whitelist."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def sanitize_filename(filename: str) -> str:
    """
    Replace unsafe characters with underscores.
    Limits result to 255 characters.
    Does NOT change the extension.
    """
    safe = _UNSAFE_CHARS_RE.sub("_", filename)
    return safe[:255]
