"""
forensiq/models/device.py
--------------------------
Device and AdapterProfile ORM models.

Phase 1: Schema defined. Populated in Phase 4 (adapter layer).
"""

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.database import Base

if TYPE_CHECKING:
    from forensiq.models.evidence import EvidenceItem


class Device(Base):
    """
    Source device identification result for an evidence item.
    Populated by the adapter layer after identification.
    Fields are set only when information is actually known — never invented.
    """
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )
    claimed_vendor: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    firmware: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    identification_confidence: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    identification_basis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    adapter_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    adapter_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    capability_status: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="device"
    )

    def __repr__(self) -> str:
        return (
            f"<Device id={self.id!r} vendor={self.claimed_vendor!r} "
            f"adapter={self.adapter_id!r}>"
        )


class AdapterProfile(Base):
    """
    Static capability record for each registered vendor adapter.
    Populated at application startup from the adapter registry.
    """
    __tablename__ = "adapter_profiles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    adapter_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    adapter_version: Mapped[str] = mapped_column(String(50), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    supported_profile: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    input_types_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    capabilities_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tested: Mapped[bool] = mapped_column(default=False, nullable=False)
    test_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    limitations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<AdapterProfile adapter_id={self.adapter_id!r} tested={self.tested!r}>"
