"""
forensiq/services/adapter_service.py
-------------------------------------
Vendor adapter orchestration and evidence analysis service.

Detects the appropriate adapter for an evidence item's working copy,
executes metadata extraction, updates evidence records, and logs custody events.

Phase 4: Fully implemented.
"""

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

import forensiq.config as _cfg
from forensiq.adapters.base import AdapterResponse, BaseAdapter
from forensiq.adapters.registry import get_registry
from forensiq.constants import EvidenceStatus
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.metadata import MetadataRecord
from forensiq.services.metadata_service import persist_metadata

logger = logging.getLogger(__name__)


def get_working_copy_path(session: Session, evidence_id: str) -> Optional[Path]:
    """Resolve the absolute Path of the working copy for *evidence_id*."""
    wc = (
        session.query(WorkingCopy)
        .filter_by(evidence_id=evidence_id)
        .order_by(WorkingCopy.created_at_utc.desc())
        .first()
    )
    if not wc or not wc.relative_path:
        return None

    return _cfg.VAULT_ROOT / wc.relative_path


def detect_adapter_for_evidence(session: Session, evidence_id: str) -> BaseAdapter:
    """Detect and return the best matching adapter for an evidence item."""
    wc_path = get_working_copy_path(session, evidence_id)
    if not wc_path or not wc_path.exists():
        # Fall back to checking source filename on EvidenceItem
        item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
        fake_path = Path(item.source_filename) if item else Path("unknown.bin")
        return get_registry().detect_adapter(fake_path)

    return get_registry().detect_adapter(wc_path)


def analyze_evidence(
    session: Session,
    evidence_id: str,
    actor_id: str = "Investigator",
) -> tuple[AdapterResponse, list[MetadataRecord]]:
    """
    Run adapter identification and metadata extraction on the evidence item's working copy.

    Returns:
        tuple[AdapterResponse, list[MetadataRecord]]: The adapter response and persisted records.
    """
    item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
    if not item:
        raise ValueError(f"Evidence item not found: {evidence_id}")

    wc_path = get_working_copy_path(session, evidence_id)
    if not wc_path or not wc_path.exists():
        raise FileNotFoundError(
            f"Working copy for evidence {item.evidence_number} does not exist on disk at {wc_path}"
        )

    adapter = get_registry().detect_adapter(wc_path)
    logger.info("Analyzing evidence %s with adapter %s", item.evidence_number, adapter.ADAPTER_ID)

    # Extract metadata via adapter
    response = adapter.extract_metadata(wc_path)

    records: list[MetadataRecord] = []
    if response.status == "SUPPORTED" and response.data:
        records = persist_metadata(
            session=session,
            evidence_id=item.id,
            case_id=item.case_id,
            parsed_metadata=response.data,
            actor_id=actor_id,
        )
        item.status = EvidenceStatus.ANALYZED.value
    elif response.status == "SAFE_FAILURE":
        logger.warning("Adapter %s returned SAFE_FAILURE for %s", adapter.ADAPTER_ID, item.evidence_number)
        if response.limitations:
            item.limitations = " | ".join(response.limitations)
    else:
        logger.error("Adapter analysis failed for %s: %s", item.evidence_number, response.error)

    session.flush()
    return response, records
