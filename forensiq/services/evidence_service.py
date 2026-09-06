"""
forensiq/services/evidence_service.py
---------------------------------------
Evidence import orchestration — the core Phase 2 workflow.

import_evidence() is the single public entry point for all evidence imports.
It coordinates: validation → hashing → vault storage → ORM → custody events
→ working copy → manifest.

All steps are wrapped in a single database transaction.  If any step fails
after the vault files have been written, the custody ledger reflects the
failed step, the database transaction is rolled back, but vault files
written before the failure are NOT automatically deleted (forensic safety).
The investigator must manually inspect and remediate.

Side-effect order (MUST be followed):
  1. File validation (pure, no DB, no vault writes)
  2. Source file hash (pure, no DB, no vault writes)
  3. create_evidence_dirs — vault directories created
  4. copy_to_original  — vault original written, re-hashed, verified
  5. set_read_only     — non-fatal
  6. DB commit: EvidenceItem + Acquisition + custody events 1-4(a)
  7. copy_to_working   — vault working copy written, re-hashed, verified
  8. DB: custody events 5-6, EvidenceItem.status → WORKING_COPY_READY
  9. write_manifest    — JSON manifest written to vault
  10. DB commit

Phase 2: Fully implemented.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import forensiq.config as _cfg
from forensiq.constants import CustodyAction, EvidenceStatus, EvidenceType, WorkingCopyStatus
from forensiq.database import session_scope
from forensiq.models.evidence import Acquisition, EvidenceItem, WorkingCopy
from forensiq.services.custody_service import record_event
from forensiq.services.hashing_service import HashResult, HashingError, hash_file
from forensiq.services.vault_service import (
    EvidencePaths,
    VaultError,
    copy_to_original,
    copy_to_working,
    create_evidence_dirs,
    set_read_only,
)
from forensiq.utils.file_utils import FileValidationError, sanitize_filename, validate_evidence_file
from forensiq.utils.manifest_utils import write_manifest
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


class EvidenceImportError(Exception):
    """Raised when evidence import cannot be completed.  Always human-readable."""


@dataclass
class ImportResult:
    """Return value of import_evidence()."""
    evidence_id: str
    evidence_number: str
    original_sha256: str
    original_md5: str
    file_size_bytes: int
    working_copy_path: Path
    vault_paths: EvidencePaths
    manifest_sha256: str


def _build_evidence_number(case_id_short: str, n: int) -> str:
    """Auto-generate an evidence number like EVD-0001 if none supplied."""
    return f"EVD-{n:04d}"


def _get_next_evidence_number(session, case_id: str) -> str:
    """Return the next auto-generated evidence number for *case_id*."""
    from sqlalchemy import func
    count = session.query(func.count(EvidenceItem.id)).filter(
        EvidenceItem.case_id == case_id
    ).scalar() or 0
    return _build_evidence_number(case_id[:8], count + 1)


def import_evidence(
    case_id: str,
    source_path: Path,
    investigator: str,
    evidence_number: Optional[str] = None,
    description: Optional[str] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> ImportResult:
    """
    Import a single evidence file into ForensIQ Vault.

    Arguments:
        case_id:         UUID string of the target Case.
        source_path:     Absolute path to the file to import.
        investigator:    Name of the importing investigator.
        evidence_number: Optional custom evidence number. Auto-generated if None.
        description:     Optional analyst description / exhibit note.
        progress_cb:     Optional callback(step_label: str, bytes_done: int, bytes_total: int).
                         Called during hashing and copying steps.

    Returns:
        ImportResult on success.

    Raises:
        EvidenceImportError on any validation or integrity failure.
        (Other exceptions propagate — the caller should treat them as unexpected failures.)
    """
    source_path = Path(source_path)
    investigator = investigator.strip()
    if not investigator:
        raise EvidenceImportError("Investigator name must not be empty.")

    # -----------------------------------------------------------------------
    # 1. File validation (pure — no writes)
    # -----------------------------------------------------------------------
    try:
        validate_evidence_file(source_path)
    except FileValidationError as e:
        raise EvidenceImportError(str(e)) from e

    # -----------------------------------------------------------------------
    # 2. Assign UUIDs
    # -----------------------------------------------------------------------
    evidence_id = str(uuid.uuid4())
    acquisition_id = str(uuid.uuid4())
    import_time = now_utc()

    # -----------------------------------------------------------------------
    # 3. Hash source file
    # -----------------------------------------------------------------------
    def _progress_hash(done: int, total: int) -> None:
        if progress_cb:
            progress_cb("Hashing source file…", done, total)

    logger.info("Hashing source file: %s", source_path)
    try:
        source_hash: HashResult = hash_file(source_path, _progress_hash)
    except HashingError as e:
        raise EvidenceImportError(f"Cannot hash source file: {e}") from e

    logger.info(
        "Source hash: sha256=%s md5=%s size=%d",
        source_hash.sha256, source_hash.md5, source_hash.size_bytes,
    )

    # -----------------------------------------------------------------------
    # 4. Create vault directories
    # -----------------------------------------------------------------------
    try:
        paths = create_evidence_dirs(case_id, evidence_id)
    except Exception as e:
        raise EvidenceImportError(f"Cannot create vault directories: {e}") from e

    # -----------------------------------------------------------------------
    # 5. Copy to vault original + verify
    # -----------------------------------------------------------------------
    def _progress_copy_orig(done: int, total: int) -> None:
        if progress_cb:
            progress_cb("Verifying vault copy…", done, total)

    logger.info("Copying to vault original: %s", paths.original_dir)
    try:
        copy_to_original(source_path, paths, source_hash.sha256, _progress_copy_orig)
    except VaultError as e:
        raise EvidenceImportError(str(e)) from e

    # -----------------------------------------------------------------------
    # 6. Set read-only on original
    # -----------------------------------------------------------------------
    read_only_success = set_read_only(paths.original_file)

    # -----------------------------------------------------------------------
    # 7. Persist EvidenceItem, Acquisition, and first custody events (PHASE A)
    # -----------------------------------------------------------------------
    sanitized = sanitize_filename(source_path.name)
    orig_rel = str(paths.original_file.relative_to(_cfg.VAULT_ROOT))

    with session_scope() as session:
        # Determine evidence number
        ev_number = evidence_number or _get_next_evidence_number(session, case_id)

        # Validate uniqueness within case
        existing = session.query(EvidenceItem).filter_by(
            case_id=case_id, evidence_number=ev_number
        ).first()
        if existing:
            raise EvidenceImportError(
                f"Evidence number '{ev_number}' already exists in this case."
            )

        # EvidenceItem
        evidence_item = EvidenceItem(
            id=evidence_id,
            case_id=case_id,
            evidence_number=ev_number,
            source_filename=source_path.name,
            sanitized_filename=sanitized,
            evidence_type=EvidenceType.VIDEO_FILE.value,
            source_description=description,
            original_relative_path=orig_rel,
            file_size_bytes=source_hash.size_bytes,
            original_sha256=source_hash.sha256,
            original_md5=source_hash.md5,
            status=EvidenceStatus.HASHED.value,
            imported_by=investigator,
            imported_at_utc=import_time,
        )
        session.add(evidence_item)

        # Acquisition record
        acquisition = Acquisition(
            id=acquisition_id,
            evidence_id=evidence_id,
            method="LOCAL_FILE_IMPORT",
            source_identifier=str(source_path),
            started_at_utc=import_time,
            completed_at_utc=now_utc(),
            operator_id=investigator,
            tool_version=_cfg.TOOL_VERSION,
        )
        session.add(acquisition)

        # Custody event: EVIDENCE_IMPORTED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=CustodyAction.EVIDENCE_IMPORTED,
            reason="Evidence file accepted and validated",
            details={
                "source_filename": source_path.name,
                "source_size_bytes": source_hash.size_bytes,
                "acquisition_method": "LOCAL_FILE_IMPORT",
            },
        )

        # Custody event: HASH_CALCULATED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=CustodyAction.HASH_CALCULATED,
            reason="SHA-256 and MD5 computed from source file before vault storage",
            output_sha256=source_hash.sha256,
            details={
                "sha256": source_hash.sha256,
                "md5": source_hash.md5,
                "size_bytes": source_hash.size_bytes,
                "note": "MD5 included for legacy compatibility only. SHA-256 is primary.",
            },
        )

        # Custody event: ORIGINAL_PRESERVED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=CustodyAction.ORIGINAL_PRESERVED,
            reason="Evidence file copied to vault original directory",
            output_sha256=source_hash.sha256,
            details={
                "vault_relative_path": orig_rel,
                "hash_verified_after_copy": True,
            },
        )

        # Custody event: READ_ONLY_SET or READ_ONLY_FAILED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=(
                CustodyAction.READ_ONLY_SET
                if read_only_success
                else CustodyAction.READ_ONLY_FAILED
            ),
            reason=(
                "Original vault copy set to read-only successfully."
                if read_only_success
                else "Failed to set read-only on vault copy — "
                     "file system may not support it or permissions are restricted."
            ),
        )

    # -----------------------------------------------------------------------
    # 8. Copy to working copy + verify
    # -----------------------------------------------------------------------
    def _progress_copy_work(done: int, total: int) -> None:
        if progress_cb:
            progress_cb("Creating working copy…", done, total)

    logger.info("Creating working copy: %s", paths.working_copy_dir)
    try:
        wc_hash = copy_to_working(paths, source_hash.sha256, _progress_copy_work)
    except VaultError as e:
        raise EvidenceImportError(str(e)) from e

    wc_rel = str(paths.working_copy_file.relative_to(_cfg.VAULT_ROOT))

    # -----------------------------------------------------------------------
    # 9. Persist WorkingCopy record + remaining custody events (PHASE B)
    # -----------------------------------------------------------------------
    with session_scope() as session:
        # Update evidence item status
        ev = session.query(EvidenceItem).filter_by(id=evidence_id).first()
        if ev:
            ev.status = EvidenceStatus.WORKING_COPY_READY.value

        # WorkingCopy record
        wc = WorkingCopy(
            evidence_id=evidence_id,
            relative_path=wc_rel,
            sha256=wc_hash.sha256,
            md5=wc_hash.md5,
            created_at_utc=now_utc(),
            verification_status=WorkingCopyStatus.VERIFIED.value,
        )
        session.add(wc)

        # Custody event: WORKING_COPY_CREATED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=CustodyAction.WORKING_COPY_CREATED,
            reason="Working copy created from vault original",
            output_sha256=wc_hash.sha256,
            details={"vault_relative_path": wc_rel},
        )

        # Custody event: WORKING_COPY_VERIFIED
        record_event(
            session,
            case_id=case_id,
            evidence_id=evidence_id,
            actor_id=investigator,
            action=CustodyAction.WORKING_COPY_VERIFIED,
            reason="Working copy SHA-256 verified against original",
            input_sha256=source_hash.sha256,
            output_sha256=wc_hash.sha256,
            details={
                "match": True,
                "original_sha256": source_hash.sha256,
                "working_copy_sha256": wc_hash.sha256,
            },
        )

    # -----------------------------------------------------------------------
    # 10. Write manifest
    # -----------------------------------------------------------------------
    manifest_data = {
        "generated_at_utc": to_iso8601(now_utc()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_number": ev_number,
        "original_filename": source_path.name,
        "original_sha256": source_hash.sha256,
        "original_md5": source_hash.md5,
        "original_size_bytes": source_hash.size_bytes,
        "working_copy_sha256": wc_hash.sha256,
        "working_copy_relative_path": wc_rel,
        "original_relative_path": orig_rel,
        "imported_by": investigator,
        "imported_at_utc": to_iso8601(import_time),
        "description": description or "",
        "read_only_set": read_only_success,
    }
    try:
        manifest_sha256 = write_manifest(paths.manifest_path, manifest_data)
    except OSError as e:
        # Non-fatal — log and continue; integrity is preserved via DB
        logger.warning("Failed to write manifest: %s", e)
        manifest_sha256 = ""

    logger.info("Evidence import complete. evidence_id=%s", evidence_id)
    return ImportResult(
        evidence_id=evidence_id,
        evidence_number=ev_number,
        original_sha256=source_hash.sha256,
        original_md5=source_hash.md5,
        file_size_bytes=source_hash.size_bytes,
        working_copy_path=paths.working_copy_file,
        vault_paths=paths,
        manifest_sha256=manifest_sha256,
    )


def list_evidence(case_id: str) -> list[EvidenceItem]:
    """Return all evidence items for *case_id*, ordered by imported_at_utc."""
    from forensiq.database import get_session
    session = get_session()
    try:
        return (
            session.query(EvidenceItem)
            .filter_by(case_id=case_id)
            .order_by(EvidenceItem.imported_at_utc)
            .all()
        )
    finally:
        session.close()


def get_evidence_by_id(evidence_id: str) -> Optional[EvidenceItem]:
    """Return an EvidenceItem by its UUID, or None if not found."""
    from forensiq.database import get_session
    session = get_session()
    try:
        return session.query(EvidenceItem).filter_by(id=evidence_id).first()
    finally:
        session.close()
