"""
forensiq/adapters/base.py
--------------------------
Abstract base class for all vendor adapters.

Every adapter must implement all abstract methods and include:
- status
- confidence
- basis
- warnings
- limitations
- adapter_id
- adapter_version

No adapter may claim "Supported" unless marked tested=True with a
controlled test reference.

Phase 1: Interface defined. Implementations added in Phase 4 and Phase 8.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class AdapterResponse:
    """
    Standardised response returned by every adapter method.
    Fields left as None indicate 'not available' — never invent them.
    """
    status: str                          # SUPPORTED, UNSUPPORTED, PARTIAL, FAILED, UNKNOWN
    confidence: str                      # HIGH, MEDIUM, LOW, NONE
    basis: str                           # How identification was determined
    adapter_id: str
    adapter_version: str
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class BaseAdapter(ABC):
    """
    Abstract base for all vendor adapters.
    All analysis must operate on a verified working copy — never original evidence.
    """

    ADAPTER_ID: str = "base"
    ADAPTER_VERSION: str = "0.0.0"

    @abstractmethod
    def identify(self, source_path: Path) -> AdapterResponse:
        """Attempt to identify the source type and vendor."""

    @abstractmethod
    def capabilities(self) -> AdapterResponse:
        """Return the capability matrix for this adapter."""

    @abstractmethod
    def extract_metadata(self, working_copy_path: Path) -> AdapterResponse:
        """Extract metadata from the working copy. Never from original evidence."""

    def inventory(self, working_copy_path: Path) -> AdapterResponse:
        """List contents of the source (optional override)."""
        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis="inventory() not implemented for this adapter",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            limitations=["inventory() not implemented"],
        )

    def extract_media(
        self, working_copy_path: Path, destination_path: Path
    ) -> AdapterResponse:
        """Extract media streams (optional override)."""
        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis="extract_media() not implemented for this adapter",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            limitations=["extract_media() not implemented"],
        )

    def recover(
        self, working_copy_path: Path, options: Optional[dict] = None
    ) -> AdapterResponse:
        """
        Attempt experimental recovery (P2 only).
        Default implementation returns UNSUPPORTED.
        No adapter may claim recovery support without a controlled test reference.
        """
        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis="Recovery not supported by this adapter",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            limitations=[
                "Recovery is P2/experimental only.",
                "Overwritten or encrypted footage may be unrecoverable.",
            ],
        )

    def validate(self, working_copy_path: Path) -> AdapterResponse:
        """Validate the working copy (optional override)."""
        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis="validate() not implemented for this adapter",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
        )
