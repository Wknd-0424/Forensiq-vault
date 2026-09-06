"""
forensiq/services/case_service.py
-----------------------------------
Business logic for forensic case management.

Phase 1: Fully implemented.
  - create_case()
  - list_cases()
  - get_case()
  - update_case_status()
"""

import logging
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from forensiq.constants import CaseStatus, CustodyAction
from forensiq.models.case import Case
from forensiq.services.custody_service import record_event
from forensiq.utils.utc_utils import now_utc

logger = logging.getLogger(__name__)


class CaseValidationError(ValueError):
    """Raised when case input fails validation."""


def _validate_case_number(case_number: str) -> None:
    """Case number must be non-empty and ≤ 100 characters."""
    s = case_number.strip()
    if not s:
        raise CaseValidationError("Case number cannot be empty.")
    if len(s) > 100:
        raise CaseValidationError("Case number must be 100 characters or fewer.")


def _validate_title(title: str) -> None:
    s = title.strip()
    if not s:
        raise CaseValidationError("Case title cannot be empty.")
    if len(s) > 500:
        raise CaseValidationError("Case title must be 500 characters or fewer.")


def _validate_investigator(name: str) -> None:
    s = name.strip()
    if not s:
        raise CaseValidationError("Investigator name cannot be empty.")


def create_case(
    session: Session,
    case_number: str,
    title: str,
    investigator_name: str,
    description: Optional[str] = None,
    authority_reference: Optional[str] = None,
) -> Case:
    """
    Create a new forensic case and record the initial CASE_CREATED
    custody event.

    Returns the persisted Case object.
    Raises CaseValidationError on invalid input.
    """
    # --- Input validation ---
    case_number = case_number.strip()
    title = title.strip()
    investigator_name = investigator_name.strip()
    _validate_case_number(case_number)
    _validate_title(title)
    _validate_investigator(investigator_name)

    # --- Duplicate check ---
    existing = (
        session.query(Case)
        .filter(Case.case_number == case_number)
        .first()
    )
    if existing:
        raise CaseValidationError(
            f"Case number '{case_number}' already exists (ID: {existing.id})."
        )

    # --- Create case ---
    now = now_utc()
    case = Case(
        id=str(uuid.uuid4()),
        case_number=case_number,
        title=title,
        description=description.strip() if description else None,
        authority_reference=authority_reference.strip() if authority_reference else None,
        status=CaseStatus.ACTIVE,
        created_by=investigator_name,
        created_at_utc=now,
        updated_at_utc=now,
    )
    session.add(case)
    session.flush()  # Get case.id before recording custody event

    # --- Record CASE_CREATED custody event ---
    record_event(
        session=session,
        case_id=case.id,
        action=CustodyAction.CASE_CREATED,
        actor_id=investigator_name,
        reason="Forensic case opened",
        details={
            "case_number": case.case_number,
            "title": case.title,
            "authority_reference": case.authority_reference,
        },
    )

    logger.info(
        "Case created: id=%s number=%s by=%s",
        case.id, case.case_number, investigator_name,
    )
    return case


def list_cases(session: Session) -> list[Case]:
    """Return all cases ordered by creation time descending."""
    return (
        session.query(Case)
        .order_by(Case.created_at_utc.desc())
        .all()
    )


def get_case(session: Session, case_id: str) -> Optional[Case]:
    """Return a Case by its UUID, or None if not found."""
    return session.query(Case).filter(Case.id == case_id).first()


def get_case_by_id(case_id: str) -> Optional[Case]:
    """Return a Case by its UUID in a self-closing session, or None if not found."""
    from forensiq.database import session_scope
    with session_scope() as session:
        return get_case(session, case_id)


def get_case_by_number(session: Session, case_number: str) -> Optional[Case]:
    """Return a Case by its human-readable case number, or None if not found."""
    return (
        session.query(Case)
        .filter(Case.case_number == case_number)
        .first()
    )


def update_case_status(
    session: Session, case_id: str, new_status: CaseStatus, actor: str
) -> Case:
    """Update the status of an existing case."""
    case = get_case(session, case_id)
    if case is None:
        raise CaseValidationError(f"Case '{case_id}' not found.")
    case.status = new_status
    case.updated_at_utc = now_utc()
    return case


def get_case_stats(session: Session) -> dict:
    """Return summary statistics for the dashboard."""
    total = session.query(Case).count()
    active = session.query(Case).filter(Case.status == CaseStatus.ACTIVE).count()
    closed = session.query(Case).filter(Case.status == CaseStatus.CLOSED).count()
    return {"total": total, "active": active, "closed": closed}
