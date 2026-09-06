"""
forensiq/models/detection.py
-----------------------------
AIDetection ORM model.

Phase 1: Schema defined. Populated in Phase 6 (AI triage).

IMPORTANT CONSTRAINTS:
- AI runs only on verified working copies or derivatives.
- Face recognition is NOT implemented and must NOT be added.
- Default reviewer_status is PENDING.
- Only CONFIRMED detections appear as analyst-confirmed findings in reports.
- AI outputs are triage aids; human review is mandatory.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.constants import ReviewerStatus
from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.timeline import VideoSegment


class AIDetection(Base):
    """
    A single object detection result from the AI triage module.
    Allowed classes: 'person', 'vehicle' (and subtypes), 'motion'.
    Face detection and face recognition are explicitly prohibited.
    """
    __tablename__ = "ai_detections"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    segment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("video_segments.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    model_name: Mapped[str] = mapped_column(String(200), nullable=False)
    model_version: Mapped[str] = mapped_column(String(100), nullable=False)
    model_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    class_name: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    frame_number: Mapped[int] = mapped_column(Integer, nullable=False)
    frame_timestamp: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    bbox_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # [x,y,w,h]
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    reviewer_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    reviewer_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ReviewerStatus.PENDING
    )
    reviewed_at_utc: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime(), nullable=True
    )

    segment: Mapped["VideoSegment"] = relationship(
        "VideoSegment", back_populates="ai_detections"
    )

    def __repr__(self) -> str:
        return (
            f"<AIDetection id={self.id!r} class={self.class_name!r} "
            f"conf={self.confidence:.2f} status={self.reviewer_status!r}>"
        )
