"""
forensiq/models/metadata.py
----------------------------
MetadataRecord ORM model.

Stores individual metadata key-value pairs extracted from evidence.
Each record preserves the raw value exactly as returned by the tool.
Normalized values are stored separately and never overwrite raw values.

Phase 1: Schema defined. Populated in Phase 4.
"""

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.database import Base

if TYPE_CHECKING:
    from forensiq.models.evidence import EvidenceItem


class MetadataRecord(Base):
    """
    A single metadata field extracted from an evidence item.
    Missing or unknown values must be stored as the string 'Unknown'
    or 'Not Present' — never as invented data.
    """
    __tablename__ = "metadata_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    namespace: Mapped[str] = mapped_column(String(100), nullable=False)   # e.g. "ffprobe"
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_reference: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    warning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="metadata_records"
    )

    def __repr__(self) -> str:
        return (
            f"<MetadataRecord evidence_id={self.evidence_id!r} "
            f"key={self.key!r} raw={self.raw_value!r}>"
        )
