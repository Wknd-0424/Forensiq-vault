"""
forensiq/models/custody.py
--------------------------
Hash-linked chain-of-custody ledger model.

Every forensically significant action creates a CustodyEvent.
Events are linked by their SHA-256 hashes to form a tamper-evident chain.

Phase 1: Fully implemented (schema + relationships).
Chain construction and verification logic lives in custody_service.py.

LIMITATION:
"This custody ledger is tamper-evident within the application.
Stronger protection requires access controls, protected backups,
independently stored or signed checkpoints, and organisation-level
forensic procedures."
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.case import Case
    from forensiq.models.evidence import EvidenceItem


class CustodyEvent(Base):
    """
    A single node in the hash-linked chain-of-custody ledger.

    event_hash = SHA-256(canonical_json({all fields except event_hash}))
    previous_event_hash links this event to the prior event for the same
    case, forming a tamper-evident append-only chain.
    """
    __tablename__ = "custody_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    # Actor: investigator name (MVP — no FK to users in phase 1)
    actor_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action_timestamp_utc: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, index=True
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Hashes of input/output artifacts at the time of the action
    input_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    output_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tool_version: Mapped[str] = mapped_column(String(200), nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string

    # Chain linkage
    previous_event_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="custody_events")
    evidence_item: Mapped[Optional["EvidenceItem"]] = relationship(
        "EvidenceItem", back_populates="custody_events"
    )

    def __repr__(self) -> str:
        return (
            f"<CustodyEvent id={self.id!r} action={self.action!r} "
            f"case_id={self.case_id!r}>"
        )
