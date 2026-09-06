"""
forensiq/utils/hashing.py
--------------------------
Streaming SHA-256 + MD5 computation with an optional progress callback.

Design decisions:
- SHA-256 is the primary forensic hash (tamper-evident).
- MD5 is computed simultaneously for legacy DVR/NVR compatibility only.
  It is NEVER used as the sole integrity check.
- Chunk size: 1 MB — balances memory use and progress granularity.
- The progress callback receives (bytes_read: int, total_bytes: int).
  It is called every chunk and once more on completion (bytes_read == total_bytes).
- This module has NO side effects — it only reads, never writes.
- Raises HashingError (not IOError directly) so callers can display
  forensic-specific error messages.

Phase 2: Fully implemented.
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

CHUNK_SIZE = 1024 * 1024  # 1 MB


class HashingError(Exception):
    """Raised when a file cannot be hashed (IO error, permission denied, etc.)."""


@dataclass(frozen=True)
class HashResult:
    """
    The result of hashing a file.
    All fields are always populated — never None.
    sha256 is the primary forensic identifier.
    md5 is stored for legacy compatibility only.
    """
    sha256: str          # 64-character lowercase hex
    md5: str             # 32-character lowercase hex
    size_bytes: int      # File size at time of hashing


def hash_file(
    path: Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> HashResult:
    """
    Compute SHA-256 and MD5 of *path* by reading it in 1 MB chunks.

    Arguments:
        path:        Path to the file to hash. Must be readable.
        progress_cb: Optional callback(bytes_read, total_bytes).
                     Called every chunk and once on completion.

    Returns:
        HashResult with sha256, md5, size_bytes.

    Raises:
        HashingError if the file cannot be read (wraps the original exception).
        HashingError if size_bytes == 0 (empty file).
    """
    path = Path(path)
    try:
        total = path.stat().st_size
    except OSError as e:
        raise HashingError(f"Cannot stat '{path}': {e}") from e

    if total == 0:
        raise HashingError(f"File is empty: '{path}'")

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    bytes_read = 0

    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                bytes_read += len(chunk)
                if progress_cb:
                    progress_cb(bytes_read, total)
    except OSError as e:
        raise HashingError(f"Cannot read '{path}': {e}") from e

    # Final progress callback to signal 100%
    if progress_cb and bytes_read != total:
        progress_cb(bytes_read, total)

    return HashResult(
        sha256=sha256.hexdigest(),
        md5=md5.hexdigest(),
        size_bytes=bytes_read,
    )


def verify_file_hash(
    path: Path,
    expected_sha256: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> bool:
    """
    Re-hash *path* and compare against *expected_sha256*.

    Returns True if the hash matches exactly (case-insensitive).
    Returns False if the hash does not match.
    Raises HashingError if the file cannot be read.
    """
    result = hash_file(path, progress_cb)
    return result.sha256.lower() == expected_sha256.lower()
