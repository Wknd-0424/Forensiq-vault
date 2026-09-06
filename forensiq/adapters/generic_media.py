"""
forensiq/adapters/generic_media.py
-----------------------------------
Generic media adapter (MVP default).

Handles standard surveillance and media containers (.mp4, .avi, .mkv, .mov, etc.)
using ffprobe. All operations run on verified working copies only.

Phase 4: Fully implemented.
"""

from pathlib import Path
from typing import Optional

from forensiq.adapters.base import AdapterResponse, BaseAdapter
from forensiq.config import ALLOWED_EXTENSIONS
from forensiq.services.metadata_service import (
    MetadataExtractionError,
    parse_metadata,
    run_ffprobe,
)


class GenericMediaAdapter(BaseAdapter):
    """
    Primary MVP adapter for standard surveillance video exports and generic media.
    Uses ffprobe to extract stream, codec, and container properties.
    """

    ADAPTER_ID: str = "generic_media"
    ADAPTER_VERSION: str = "1.0.0"

    SUPPORTED_EXTENSIONS = {
        ".mp4", ".avi", ".mkv", ".mov", ".ts", ".m4v", ".dav", ".h264", ".h265"
    }

    def identify(self, source_path: Path) -> AdapterResponse:
        """
        Identify whether the file is handled by this generic media adapter.
        Evaluates file extension and accessibility.
        """
        ext = source_path.suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return AdapterResponse(
                status="SUPPORTED",
                confidence="HIGH",
                basis=f"Standard media container extension: {ext}",
                adapter_id=self.ADAPTER_ID,
                adapter_version=self.ADAPTER_VERSION,
                data={"extension": ext, "vendor": "Generic / Standard Media"},
            )

        return AdapterResponse(
            status="UNSUPPORTED",
            confidence="NONE",
            basis=f"Extension '{ext}' is not a recognized standard media container",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            warnings=[f"Unrecognized media container format: {ext}"],
        )

    def capabilities(self) -> AdapterResponse:
        """Return the capability matrix for GenericMediaAdapter."""
        return AdapterResponse(
            status="SUPPORTED",
            confidence="HIGH",
            basis="Standard ffprobe-based container and stream parsing capabilities",
            adapter_id=self.ADAPTER_ID,
            adapter_version=self.ADAPTER_VERSION,
            data={
                "vendor_name": "Generic Media / Standard DVR Export",
                "features": {
                    "container_identification": "TESTED",
                    "metadata_extraction": "TESTED",
                    "video_stream_parsing": "TESTED",
                    "audio_stream_parsing": "TESTED",
                    "timestamp_parsing": "TESTED",
                    "frame_extraction": "PLANNED",
                    "proprietary_disk_recovery": "UNSUPPORTED",
                    "proprietary_codec_transcoding": "PLACEHOLDER",
                },
                "supported_containers": sorted(list(self.SUPPORTED_EXTENSIONS)),
            },
            limitations=[
                "Cannot parse proprietary raw DVR filesystem sectors (e.g. unfinalized DHFS / Hikvision raw disks).",
                "Depends on ffprobe being available on the system.",
            ],
        )

    def extract_metadata(self, working_copy_path: Path) -> AdapterResponse:
        """
        Extract metadata from the working copy using ffprobe.
        Never touches the original evidence.
        """
        try:
            raw_data = run_ffprobe(working_copy_path)
            parsed = parse_metadata(raw_data)
            return AdapterResponse(
                status="SUPPORTED",
                confidence="HIGH",
                basis="Metadata extracted successfully via ffprobe from working copy",
                adapter_id=self.ADAPTER_ID,
                adapter_version=self.ADAPTER_VERSION,
                data=parsed,
            )
        except MetadataExtractionError as exc:
            return AdapterResponse(
                status="FAILED",
                confidence="NONE",
                basis="ffprobe extraction failed on working copy",
                adapter_id=self.ADAPTER_ID,
                adapter_version=self.ADAPTER_VERSION,
                error=str(exc),
                warnings=[str(exc)],
                limitations=["ffprobe must be installed to extract video metadata"],
            )
        except Exception as exc:
            return AdapterResponse(
                status="FAILED",
                confidence="NONE",
                basis="Unexpected error during metadata extraction",
                adapter_id=self.ADAPTER_ID,
                adapter_version=self.ADAPTER_VERSION,
                error=str(exc),
                warnings=[f"Unexpected error: {exc}"],
            )
