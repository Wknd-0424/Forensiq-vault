"""
forensiq/models/recovery.py
----------------------------
RecoveryResult ORM model.

Phase 1: Schema defined. Recovery is P2/experimental only.

WARNING:
"Overwritten, encrypted, physically damaged, incomplete or heavily fragmented
footage may be unrecoverable. Recovery outcomes must be validated against
controlled ground truth where available."
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.constants import RecoveryStatus
from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.evidence import EvidenceItem


class RecoveryResult(Base):
    """
    Result of an experimental recovery attempt on an evidence item.
    Default status is NOT_ATTEMPTED. This module is P2/experimental.
    """
    __tablename__ = "recovery_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=RecoveryStatus.NOT_ATTEMPTED
    )
    recovered_relative_path: Mapped[Optional[str]] = mapped_column(
        String(1000), nullable=True
    )
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    recovered_duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_ranges_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    limitations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="recovery_results"
    )

    def __repr__(self) -> str:
        return (
            f"<RecoveryResult id={self.id!r} status={self.status!r} "
            f"method={self.method!r}>"
        )
