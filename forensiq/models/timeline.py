"""
forensiq/models/timeline.py
----------------------------
VideoSegment and TimelineEvent ORM models.

Phase 1: Schema defined. Populated in Phase 5.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.constants import AnalystStatus, NormalizationMethod, TimelineEventType
from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.evidence import EvidenceItem
    from forensiq.models.case import Case
    from forensiq.models.detection import AIDetection


class VideoSegment(Base):
    """
    A contiguous video segment within an evidence item.
    Raw timestamps are preserved exactly as found.
    Normalized timestamps are stored separately.
    """
    __tablename__ = "video_segments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    channel_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_start_offset: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    source_end_offset: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    raw_start_time: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    raw_end_time: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    normalized_start_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )
    normalized_end_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )
    timestamp_uncertainty_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    codec: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    frame_rate: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    parse_status: Mapped[str] = mapped_column(String(50), nullable=False, default="UNKNOWN")
    warnings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem", back_populates="video_segments"
    )
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(
        "TimelineEvent", back_populates="segment", cascade="all, delete-orphan"
    )
    ai_detections: Mapped[list["AIDetection"]] = relationship(
        "AIDetection", back_populates="segment", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<VideoSegment id={self.id!r} channel={self.channel_id!r} "
            f"status={self.parse_status!r}>"
        )


class TimelineEvent(Base):
    """
    A timestamped event on the forensic timeline.
    Raw timestamps are preserved; normalized UTC is a derived value.
    Multi-camera correlation is flagged for analyst review — never asserted.
    """
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    segment_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("video_segments.id", ondelete="SET NULL"),
        nullable=True
    )
    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False, default=TimelineEventType.MANUAL_ENTRY
    )
    raw_timestamp: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    normalized_timestamp_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )
    offset_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    normalization_method: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, default=NormalizationMethod.NONE
    )
    uncertainty_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    analyst_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=AnalystStatus.PENDING
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    segment: Mapped[Optional["VideoSegment"]] = relationship(
        "VideoSegment", back_populates="timeline_events"
    )

    def __repr__(self) -> str:
        return (
            f"<TimelineEvent id={self.id!r} type={self.event_type!r} "
            f"analyst_status={self.analyst_status!r}>"
        )
