"""
forensiq/adapters/unknown_source.py
-----------------------------------
Fallback adapter for unrecognised, proprietary, or unsupported formats.

Follows the forensic rule:
"Safe failure — no invented metadata, clear explanation of unsupported features."

Phase 4: Fully implemented.
"""

from pathlib import Path

from forensiq.adapters.base import AdapterResponse, BaseAdapter


class UnknownSourceAdapter(BaseAdapter):
    """
    Fallback adapter invoked when no specific vendor or generic media
    adapter recognizes the file or disk structure.
    Guarantees safe failure without crashing or inventing metadata.
    """

    ADAPTER_ID: str = "unknown_source"
    ADAPTER_VERSION: str = "1.0.0"

    def identify(self, source_path: Path) -> AdapterResponse:
        """Always returns SAFE_FAILURE with explanatory notes."""
        return AdapterResponse(
            status="SAFE_FAILURE",
            confidence="NONE",
            basis="No registered vendor adapter recognized the container signature or extension",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            warnings=[f"Unrecognized file format or proprietary stream: {source_path.name}"],
            limitations=[
                "Evidence may require a vendor-specific proprietary player or raw disk parser.",
                "Original file integrity remains preserved and hashed in the vault.",
            ],
            data={"source_filename": source_path.name, "suffix": source_path.suffix},
        )

    def capabilities(self) -> AdapterResponse:
        """Capability matrix indicating unsupported status for all operations."""
        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis="Unknown Source Fallback Adapter",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            data={
                "vendor_name": "Unknown / Unsupported Format",
                "features": {
                    "container_identification": "SAFE_FAILURE",
                    "metadata_extraction": "UNSUPPORTED",
                    "video_stream_parsing": "UNSUPPORTED",
                    "proprietary_disk_recovery": "UNSUPPORTED",
                },
            },
            limitations=[
                "Cannot parse metadata without a compatible vendor adapter.",
                "Safe failure ensures no invented or corrupt metadata enters the case ledger.",
            ],
        )

    def extract_metadata(self, working_copy_path: Path) -> AdapterResponse:
        """Return safe failure for metadata extraction."""
        return AdapterResponse(
            status="SAFE_FAILURE",
            confidence="NONE",
            basis="Cannot extract metadata from unrecognized or unsupported source",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            warnings=["Metadata extraction is unsupported for this format"],
            limitations=[
                "No metadata could be extracted without an appropriate vendor decoder."
            ],
        )
