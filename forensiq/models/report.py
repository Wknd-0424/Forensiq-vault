"""
forensiq/models/report.py
--------------------------
Report ORM model.

Phase 1: Schema defined. Report generation implemented in Phase 7.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from forensiq.database import Base, UTCDateTime

if TYPE_CHECKING:
    from forensiq.models.case import Case


class Report(Base):
    """
    Tracks every generated forensic report (HTML, JSON, PDF).
    Reports are stored in vault/reports/{case_id}/.
    The SHA-256 of each report is computed and stored for integrity.
    """
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # HTML, JSON, PDF
    relative_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    manifest_relative_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    manifest_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    generator_version: Mapped[str] = mapped_column(String(200), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(200), nullable=False)
    generated_at_utc: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    def __repr__(self) -> str:
        return (
            f"<Report id={self.id!r} type={self.report_type!r} "
            f"case_id={self.case_id!r}>"
        )
