"""
forensiq/utils/manifest_utils.py
----------------------------------
JSON evidence manifest — atomic write with SHA-256 of the manifest itself.

A manifest is written for every evidence item after the working copy is
verified.  It documents the entire import event in a self-contained JSON file
that can be validated independently of the database.

Manifest schema:
  {
    "forensiq_vault_version": "0.1.0",
    "manifest_schema": "1.0",
    "generated_at_utc": "<ISO-8601>",
    "case_id": "...",
    "evidence_id": "...",
    "evidence_number": "...",
    "original_filename": "...",
    "original_sha256": "...",
    "original_md5": "...",
    "original_size_bytes": 0,
    "working_copy_sha256": "...",
    "working_copy_relative_path": "...",
    "original_relative_path": "...",
    "imported_by": "...",
    "imported_at_utc": "<ISO-8601>",
    "description": "...",
    "read_only_set": true/false
  }

Phase 2: Fully implemented.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from forensiq.config import APP_VERSION


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_manifest(path: Path, data: dict[str, Any]) -> str:
    """
    Write *data* as an indented JSON manifest to *path*.

    Uses an atomic write pattern (write to temp file → rename) to prevent
    partial manifests if the process is interrupted.

    Returns the SHA-256 hex digest of the written manifest content.
    Raises OSError on filesystem errors.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Inject standard header fields
    enriched = {
        "forensiq_vault_version": APP_VERSION,
        "manifest_schema": "1.0",
        **data,
    }

    content = json.dumps(enriched, indent=2, sort_keys=True, ensure_ascii=False)
    content_bytes = content.encode("utf-8")
    manifest_sha256 = _sha256_of_bytes(content_bytes)

    # Atomic write: temp file in same directory → rename
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=".manifest_tmp_", suffix=".json"
    )
    try:
        os.write(tmp_fd, content_bytes)
        os.close(tmp_fd)
        os.replace(tmp_path, path)  # atomic on POSIX; near-atomic on Windows
    except Exception:
        # Clean up temp file on failure
        try:
            os.close(tmp_fd)
        except OSError:
            pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return manifest_sha256


def read_manifest(path: Path) -> dict[str, Any]:
    """
    Read and parse a JSON manifest from *path*.
    Raises OSError if the file cannot be read, json.JSONDecodeError if invalid.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_manifest_hash(path: Path, expected_sha256: str) -> bool:
    """
    Re-read *path* and verify its SHA-256 matches *expected_sha256*.
    Returns True on match, False on mismatch.
    """
    try:
        content = path.read_bytes()
        actual = _sha256_of_bytes(content)
        return actual.lower() == expected_sha256.lower()
    except OSError:
        return False
