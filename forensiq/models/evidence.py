"""
forensiq/models/evidence.py
----------------------------
ORM models for EvidenceItem (imported file) and Acquisition (import session).

Phase 1: Schema complete. Service logic implemented in Phase 2.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.constants import EvidenceStatus, EvidenceType
from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.case import Case
    from forensiq.models.custody import CustodyEvent
    from forensiq.models.device import Device
    from forensiq.models.metadata import MetadataRecord
    from forensiq.models.timeline import VideoSegment
    from forensiq.models.recovery import RecoveryResult
    from forensiq.models.validation import ValidationRun
    from forensiq.models.detection import AIDetection


class EvidenceItem(Base):
    """
    One imported evidence file (video export, disk image, etc.).
    Original evidence is vaulted read-only and never used as analysis input.
    All analysis operates on the verified working copy.
    """
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_number: Mapped[str] = mapped_column(String(100), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    sanitized_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default=EvidenceType.UNKNOWN
    )
    source_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Vault-relative paths (never full absolute paths in UI)
    original_relative_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    file_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    original_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    original_md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=EvidenceStatus.IMPORTED
    )
    imported_by: Mapped[str] = mapped_column(String(200), nullable=False)
    imported_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    # Limitation notes from adapter / validation
    limitations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Self-referential: derivative items point to parent
    parent_evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="evidence_items")
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent", back_populates="evidence_item"
    )
    working_copies: Mapped[list["WorkingCopy"]] = relationship(
        "WorkingCopy", back_populates="evidence_item", cascade="all, delete-orphan"
    )
    device: Mapped[Optional["Device"]] = relationship(
        "Device", back_populates="evidence_item", uselist=False
    )
    metadata_records: Mapped[list["MetadataRecord"]] = relationship(
        "MetadataRecord", back_populates="evidence_item", cascade="all, delete-orphan"
    )
    video_segments: Mapped[list["VideoSegment"]] = relationship(
        "VideoSegment", back_populates="evidence_item", cascade="all, delete-orphan"
    )
    recovery_results: Mapped[list["RecoveryResult"]] = relationship(
        "RecoveryResult", back_populates="evidence_item", cascade="all, delete-orphan"
    )
    validation_runs: Mapped[list["ValidationRun"]] = relationship(
        "ValidationRun", back_populates="evidence_item", cascade="all, delete-orphan"
    )
    derivatives: Mapped[list["Derivative"]] = relationship(
        "Derivative", back_populates="parent_evidence",
        foreign_keys="Derivative.parent_evidence_id",
        cascade="all, delete-orphan",
    )
    acquisition: Mapped[Optional["Acquisition"]] = relationship(
        "Acquisition", back_populates="evidence_item", uselist=False
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceItem id={self.id!r} "
            f"filename={self.sanitized_filename!r} "
            f"status={self.status!r}>"
        )


class WorkingCopy(Base):
    """
    A verified copy of original evidence used for all analysis operations.
    SHA-256 must equal the original before analysis proceeds.
    """
    __tablename__ = "working_copies"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(50), nullable=False)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="working_copies"
    )

    def __repr__(self) -> str:
        return (
            f"<WorkingCopy id={self.id!r} "
            f"status={self.verification_status!r}>"
        )


class Derivative(Base):
    """
    A transformed output derived from a working copy (e.g. MP4 preview,
    extracted frame, AI-annotated video).  Every derivative must reference
    its parent evidence item.
    """
    __tablename__ = "derivatives"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    parent_evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    derivative_type: Mapped[str] = mapped_column(String(100), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    transform_manifest_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    parent_evidence: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="derivatives",
        foreign_keys=[parent_evidence_id],
    )

    def __repr__(self) -> str:
        return f"<Derivative id={self.id!r} type={self.derivative_type!r}>"


class Acquisition(Base):
    """
    Records the import session metadata (who, when, how, what tool).
    """
    __tablename__ = "acquisitions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )
    method: Mapped[str] = mapped_column(String(100), nullable=False)
    source_identifier: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    started_at_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )
    completed_at_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )
    operator_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    device_snapshot_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_version: Mapped[str] = mapped_column(String(200), nullable=False)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="acquisition"
    )

    def __repr__(self) -> str:
        return f"<Acquisition id={self.id!r} method={self.method!r}>"
