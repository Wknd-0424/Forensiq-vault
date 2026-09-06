"""
forensiq/services/vault_service.py
------------------------------------
Vault directory management and evidence file operations.

Responsibilities:
  - Create per-evidence vault directory structure.
  - Copy source file to vault/original/ with integrity verification.
  - Attempt to set original vault copy read-only.
  - Copy original to vault/working_copy/ with integrity verification.
  - Provide EvidencePaths dataclass for other services.

CRITICAL RULES (never relaxed):
  - NEVER move files — always copy then optionally delete.
  - NEVER copy from a working copy to create an original.
  - ALWAYS verify hash after copy before returning success.
  - ALWAYS call assert_within_vault before any write.
  - A failed read-only attempt is logged and recorded but does NOT abort.

Phase 2: Fully implemented.
"""

import logging
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import forensiq.config as _cfg
from forensiq.utils.hashing import HashResult, HashingError, hash_file, verify_file_hash
from forensiq.utils.security_utils import assert_within_vault

logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Raised when a vault operation fails for a non-trivial reason."""


@dataclass
class EvidencePaths:
    """
    Resolved, absolute paths for a single evidence item inside the vault.
    All paths are within VAULT_ROOT.
    """
    evidence_dir: Path          # vault/{case_id}/evidence/{evidence_id}/
    original_dir: Path          # .../original/
    working_copy_dir: Path      # .../working_copy/
    derivatives_dir: Path       # .../derivatives/
    manifest_path: Path         # .../manifest.json
    original_file: Optional[Path] = None       # set after copy
    working_copy_file: Optional[Path] = None   # set after copy


def create_evidence_dirs(case_id: str, evidence_id: str) -> EvidencePaths:
    """
    Create the per-evidence vault directory tree and return an EvidencePaths.
    Idempotent — safe to call if dirs already exist.

    Structure:
        vault/{case_id}/evidence/{evidence_id}/
            original/
            working_copy/
            derivatives/
    """
    VAULT_ROOT = _cfg.VAULT_ROOT
    base = VAULT_ROOT / case_id / "evidence" / evidence_id
    original_dir = base / "original"
    working_copy_dir = base / "working_copy"
    derivatives_dir = base / "derivatives"

    for d in (original_dir, working_copy_dir, derivatives_dir):
        assert_within_vault(d, VAULT_ROOT)
        d.mkdir(parents=True, exist_ok=True)

    manifest_path = base / "manifest.json"
    assert_within_vault(manifest_path, VAULT_ROOT)

    logger.debug("Evidence vault dirs created: %s", base)
    return EvidencePaths(
        evidence_dir=base,
        original_dir=original_dir,
        working_copy_dir=working_copy_dir,
        derivatives_dir=derivatives_dir,
        manifest_path=manifest_path,
    )


def copy_to_original(
    source: Path,
    paths: EvidencePaths,
    expected_sha256: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> HashResult:
    """
    Copy *source* to paths.original_dir/{source.name}.
    After copying, re-hash the destination and verify it matches *expected_sha256*.

    Sets paths.original_file on success.

    Returns the HashResult of the vault copy.
    Raises VaultError if copy fails or hash verification fails.
    """
    dest = paths.original_dir / source.name
    assert_within_vault(dest, _cfg.VAULT_ROOT)

    try:
        shutil.copy2(str(source), str(dest))
    except OSError as e:
        raise VaultError(f"Failed to copy evidence to vault: {e}") from e

    logger.debug("Original copied to: %s", dest)

    # Verify the copy
    try:
        result = hash_file(dest, progress_cb)
    except HashingError as e:
        raise VaultError(f"Cannot hash vault copy: {e}") from e

    if result.sha256.lower() != expected_sha256.lower():
        # Hash mismatch — delete the bad copy and abort
        try:
            dest.unlink()
        except OSError:
            pass
        raise VaultError(
            f"Hash mismatch after copying to vault!\n"
            f"  Expected: {expected_sha256}\n"
            f"  Got:      {result.sha256}\n"
            f"The copied file has been removed."
        )

    paths.original_file = dest
    return result


def set_read_only(path: Path) -> bool:
    """
    Attempt to set *path* read-only on disk.
    Returns True on success, False on failure (non-fatal).

    On Windows, this removes the write attribute.
    On Linux/macOS, chmod removes all write bits.

    Failure is logged as a WARNING and recorded in the custody chain,
    but does NOT abort the workflow.
    """
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
        # Remove write bits for owner, group, and others
        read_only_mode = current & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        os.chmod(path, read_only_mode)
        logger.info("Set read-only: %s", path)
        return True
    except OSError as e:
        logger.warning("Could not set read-only on '%s': %s", path, e)
        return False


def copy_to_working(
    paths: EvidencePaths,
    expected_sha256: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> HashResult:
    """
    Copy the vault original to working_copy/ and verify its hash.

    *paths.original_file* must be set (by copy_to_original).
    Sets paths.working_copy_file on success.

    Returns the HashResult of the working copy.
    Raises VaultError if the original file is not set, or if copy/hash fails.
    """
    if paths.original_file is None:
        raise VaultError("original_file is not set — call copy_to_original first.")

    dest = paths.working_copy_dir / paths.original_file.name
    assert_within_vault(dest, _cfg.VAULT_ROOT)

    try:
        shutil.copy2(str(paths.original_file), str(dest))
    except OSError as e:
        raise VaultError(f"Failed to create working copy: {e}") from e

    logger.debug("Working copy created: %s", dest)

    # Verify
    try:
        result = hash_file(dest, progress_cb)
    except HashingError as e:
        raise VaultError(f"Cannot hash working copy: {e}") from e

    if result.sha256.lower() != expected_sha256.lower():
        try:
            dest.unlink()
        except OSError:
            pass
        raise VaultError(
            f"Working copy hash mismatch!\n"
            f"  Expected: {expected_sha256}\n"
            f"  Got:      {result.sha256}\n"
            f"The working copy has been removed."
        )

    paths.working_copy_file = dest
    logger.info("Working copy verified: %s", dest)
    return result
