"""
forensiq/models/validation.py
------------------------------
ValidationRun ORM model.

Phase 1: Schema defined. Populated in Phase 4 (validation service).
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.evidence import EvidenceItem


class ValidationRun(Base):
    """
    Records the result of a forensic validation check on an evidence item.
    Validation types are defined in validation_service.py.
    """
    __tablename__ = "validation_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    validation_type: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    results_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    performed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    performed_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(200), nullable=False)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="validation_runs"
    )

    def __repr__(self) -> str:
        return (
            f"<ValidationRun id={self.id!r} type={self.validation_type!r} "
            f"status={self.status!r}>"
        )
