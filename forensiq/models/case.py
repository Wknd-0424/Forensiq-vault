"""
forensiq/models/case.py
-----------------------
ORM models for Cases and Users.

Phase 1: Fully implemented.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.constants import CaseStatus, UserRole
from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.custody import CustodyEvent
    from forensiq.models.evidence import EvidenceItem


class User(Base):
    """
    Represents an investigator or reviewer.
    MVP: Users are created ad-hoc at case-creation time (no auth system).
    Phase 8+ may add persistent user management.
    """
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), nullable=False, default=UserRole.INVESTIGATOR
    )
    created_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    def __repr__(self) -> str:
        return f"<User id={self.id!r} username={self.username!r} role={self.role!r}>"


class Case(Base):
    """
    A forensic case grouping one or more pieces of evidence.
    Each case receives a UUID and a human-readable case number.
    """
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_number: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authority_reference: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=CaseStatus.ACTIVE
    )
    # MVP: store investigator name directly (no FK to users table)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    updated_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    # Relationships
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent", back_populates="case", cascade="all, delete-orphan",
        order_by="CustodyEvent.action_timestamp_utc",
    )
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(
        "EvidenceItem", back_populates="case", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Case id={self.id!r} number={self.case_number!r} "
            f"status={self.status!r}>"
        )
