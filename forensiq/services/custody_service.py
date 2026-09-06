"""
forensiq/services/custody_service.py
--------------------------------------
Hash-linked chain-of-custody ledger management.

Every forensically significant action calls record_event().
The hash chain is built and verified here.

Chain construction:
  event_hash = SHA-256(canonical_json({all event fields except event_hash}))

Chain verification checks:
  1. Recompute each event_hash from stored fields — must match.
  2. Each event's previous_event_hash must match the prior event's event_hash.
  3. No gaps in ordering by timestamp.

LIMITATION (must be shown in UI and reports):
"This custody ledger is tamper-evident within the application. Stronger
protection requires access controls, protected backups, independently stored
or signed checkpoints, and organisation-level forensic procedures."
"""

import hashlib
import json
import logging
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from forensiq.config import TOOL_VERSION
from forensiq.constants import ChainVerificationResult, CustodyAction
from forensiq.models.custody import CustodyEvent
from forensiq.utils.canonical_json import canonical_bytes
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


def _hash_event_fields(fields: dict) -> str:
    """
    Compute SHA-256 over the canonical JSON of *fields*.
    *fields* must NOT include the 'event_hash' key itself.
    """
    raw = canonical_bytes(fields)
    return hashlib.sha256(raw).hexdigest()


def _event_to_hashable_dict(event: CustodyEvent) -> dict:
    """
    Produce the dict used to compute/verify an event's event_hash.
    Must exactly match what was used at creation time.
    All fields except event_hash are included.
    """
    return {
        "id": event.id,
        "case_id": event.case_id,
        "evidence_id": event.evidence_id,
        "actor_id": event.actor_id,
        "action": event.action,
        "action_timestamp_utc": to_iso8601(event.action_timestamp_utc),
        "reason": event.reason,
        "input_sha256": event.input_sha256,
        "output_sha256": event.output_sha256,
        "tool_version": event.tool_version,
        "details_json": event.details_json,
        "previous_event_hash": event.previous_event_hash,
    }


def get_last_event_hash(session: Session, case_id: str) -> Optional[str]:
    """
    Return the event_hash of the most recent custody event for *case_id*,
    or None if the chain is empty.
    """
    last = (
        session.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case_id)
        .order_by(CustodyEvent.action_timestamp_utc.desc())
        .first()
    )
    return last.event_hash if last else None


def record_event(
    session: Session,
    case_id: str,
    action: CustodyAction,
    actor_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    reason: Optional[str] = None,
    input_sha256: Optional[str] = None,
    output_sha256: Optional[str] = None,
    details: Optional[dict] = None,
) -> CustodyEvent:
    """
    Create and persist a new custody event with a computed event_hash.

    This is the ONLY function that should create CustodyEvent records.
    Do not create CustodyEvent objects directly outside this function.
    """
    event_id = str(uuid.uuid4())
    timestamp = now_utc()
    previous_hash = get_last_event_hash(session, case_id)
    details_json = json.dumps(details, sort_keys=True) if details else None

    # Build the fields dict used for hashing
    hashable = {
        "id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "actor_id": actor_id,
        "action": action.value,
        "action_timestamp_utc": to_iso8601(timestamp),
        "reason": reason,
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "tool_version": TOOL_VERSION,
        "details_json": details_json,
        "previous_event_hash": previous_hash,
    }
    event_hash = _hash_event_fields(hashable)

    event = CustodyEvent(
        id=event_id,
        case_id=case_id,
        evidence_id=evidence_id,
        actor_id=actor_id,
        action=action.value,
        action_timestamp_utc=timestamp,
        reason=reason,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        tool_version=TOOL_VERSION,
        details_json=details_json,
        previous_event_hash=previous_hash,
        event_hash=event_hash,
    )
    session.add(event)
    session.flush()  # assign PK without committing

    logger.debug(
        "Custody event recorded: action=%s case=%s hash=%s",
        action, case_id, event_hash[:8]
    )
    return event


def get_chain_for_case(session: Session, case_id: str) -> list[CustodyEvent]:
    """Return all custody events for *case_id* in chronological order."""
    return (
        session.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case_id)
        .order_by(CustodyEvent.action_timestamp_utc.asc())
        .all()
    )


def get_chain_for_evidence(session: Session, evidence_id: str) -> list[CustodyEvent]:
    """Return all custody events associated with *evidence_id* in chronological order."""
    return (
        session.query(CustodyEvent)
        .filter(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.action_timestamp_utc.asc())
        .all()
    )


def record_manual_event(
    session: Session,
    case_id: str,
    action: CustodyAction,
    actor_id: str,
    evidence_id: Optional[str] = None,
    reason: Optional[str] = None,
    details: Optional[dict] = None,
) -> CustodyEvent:
    """
    Record an investigator's manual custody action (e.g. CUSTODY_TRANSFERRED, ANALYST_NOTE).
    Validates required fields before writing to the hash chain.
    """
    if not actor_id or not actor_id.strip():
        raise ValueError("Actor/Investigator name is required to record a custody event.")
    if not isinstance(action, CustodyAction):
        # Allow string enum lookup
        try:
            action = CustodyAction(action)
        except ValueError:
            raise ValueError(f"Invalid custody action: {action}")

    return record_event(
        session=session,
        case_id=case_id,
        action=action,
        actor_id=actor_id.strip(),
        evidence_id=evidence_id,
        reason=reason.strip() if reason else None,
        details=details,
    )


def verify_chain(
    session: Session, case_id: str
) -> tuple[ChainVerificationResult, list[str]]:
    """
    Verify the integrity of the custody chain for *case_id*.

    Returns:
        (result_enum, list_of_error_messages)

    Verification steps:
    1. Fetch all events in chronological order.
    2. If empty → EMPTY_CHAIN.
    3. For each event:
       a. Recompute event_hash from stored fields.
       b. Compare with stored event_hash → INVALID_EVENT_HASH if mismatch.
       c. Check previous_event_hash matches prior event's event_hash
          → INVALID_PREVIOUS_LINK if mismatch.
    """
    events = (
        session.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case_id)
        .order_by(CustodyEvent.action_timestamp_utc.asc())
        .all()
    )

    if not events:
        return ChainVerificationResult.EMPTY_CHAIN, ["No custody events found for this case."]

    errors: list[str] = []
    previous_hash: Optional[str] = None

    for i, event in enumerate(events):
        hashable = _event_to_hashable_dict(event)
        computed_hash = _hash_event_fields(hashable)

        # Check 1: stored event_hash matches recomputed hash
        if computed_hash != event.event_hash:
            errors.append(
                f"Event {i+1} ({event.action}): "
                f"stored hash {event.event_hash[:8]}… does not match "
                f"recomputed hash {computed_hash[:8]}…"
            )
            return ChainVerificationResult.INVALID_EVENT_HASH, errors

        # Check 2: previous_event_hash links correctly
        if event.previous_event_hash != previous_hash:
            errors.append(
                f"Event {i+1} ({event.action}): "
                f"previous_event_hash {str(event.previous_event_hash)[:8]}… "
                f"does not match prior event hash {str(previous_hash)[:8]}…"
            )
            return ChainVerificationResult.INVALID_PREVIOUS_LINK, errors

        previous_hash = event.event_hash

    return ChainVerificationResult.VALID, []


def verify_case_chain(case_id: str) -> tuple[ChainVerificationResult, list[str]]:
    """Convenience helper to verify a case chain within a self-closing session."""
    from forensiq.database import session_scope
    with session_scope() as session:
        return verify_chain(session, case_id)


def export_custody_ledger_json(session: Session, case_id: str) -> str:
    """
    Export the full custody ledger for *case_id* as a structured JSON string.
    Includes verification metadata, genesis/latest hashes, and full event payloads.
    """
    events = get_chain_for_case(session, case_id)
    verification_result, verification_errors = verify_chain(session, case_id)

    export_payload = {
        "export_metadata": {
            "case_id": case_id,
            "exported_at_utc": to_iso8601(now_utc()),
            "tool_version": TOOL_VERSION,
            "total_events": len(events),
            "verification_result": verification_result.value,
            "verification_errors": verification_errors,
            "genesis_event_hash": events[0].event_hash if events else None,
            "latest_event_hash": events[-1].event_hash if events else None,
            "disclaimer": (
                "This custody ledger is tamper-evident within the application. "
                "Stronger protection requires access controls, protected backups, "
                "independently stored or signed checkpoints, and organisation-level "
                "forensic procedures."
            ),
        },
        "events": [
            {
                "sequence": idx + 1,
                "id": ev.id,
                "case_id": ev.case_id,
                "evidence_id": ev.evidence_id,
                "actor_id": ev.actor_id,
                "action": ev.action,
                "action_timestamp_utc": to_iso8601(ev.action_timestamp_utc),
                "reason": ev.reason,
                "input_sha256": ev.input_sha256,
                "output_sha256": ev.output_sha256,
                "tool_version": ev.tool_version,
                "details": json.loads(ev.details_json) if ev.details_json else None,
                "previous_event_hash": ev.previous_event_hash,
                "event_hash": ev.event_hash,
            }
            for idx, ev in enumerate(events)
        ],
    }
    return json.dumps(export_payload, indent=2, ensure_ascii=False)


def export_custody_ledger_csv(session: Session, case_id: str) -> str:
    """
    Export the full custody ledger for *case_id* as RFC 4180 CSV text.
    """
    import csv
    import io

    events = get_chain_for_case(session, case_id)
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "Sequence",
        "Timestamp UTC",
        "Action",
        "Actor",
        "Evidence ID",
        "Reason",
        "Input SHA-256",
        "Output SHA-256",
        "Previous Event Hash",
        "Event Hash",
        "Tool Version",
    ])
    for idx, ev in enumerate(events):
        writer.writerow([
            idx + 1,
            to_iso8601(ev.action_timestamp_utc) if ev.action_timestamp_utc else "",
            ev.action,
            ev.actor_id or "",
            ev.evidence_id or "",
            ev.reason or "",
            ev.input_sha256 or "",
            ev.output_sha256 or "",
            ev.previous_event_hash or "",
            ev.event_hash,
            ev.tool_version,
        ])
    return output.getvalue()
