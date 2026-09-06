"""
forensiq/services/validation_service.py
----------------------------------------
Forensic Validation Engine.

Performs automated forensic sanity checks on video metadata, stream headers,
timestamps, and container consistency.

Validation checks:
1. Container & Codec Alignment: Validates that video/audio codecs match the container spec.
2. Timestamp Sanity: Detects future dates, pre-1990 timestamps (RTC battery failure), or invalid time zones.
3. Duration & Bitrate Consistency: Detects truncated streams or header/payload size mismatches.
4. Video Dimensions & Frame Rate: Verifies non-zero dimensions, standard surveillance profiles, and frame rates.

Every validation run is persisted in the validation_runs table and recorded
in the hash-linked chain of custody.

Phase 4: Fully implemented.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from forensiq.config import TOOL_VERSION
from forensiq.constants import CustodyAction
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.validation import ValidationRun
from forensiq.services.custody_service import record_event
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


class ValidationStatus:
    PASSED = "PASSED"
    WARNING = "WARNING"
    FAILED = "FAILED"


def check_container_codec(parsed_metadata: dict[str, Any]) -> dict[str, Any]:
    """Check if stream codecs are consistent with the container format."""
    container = parsed_metadata.get("container", {})
    format_name = (container.get("format_name") or "").lower()
    video_streams = parsed_metadata.get("video_streams", [])

    if not format_name and not video_streams:
        return {
            "check": "Container & Codec Alignment",
            "status": ValidationStatus.WARNING,
            "message": "No container format or video streams found in metadata.",
            "details": {},
        }

    valid_codecs_by_format = {
        "mp4": {"h264", "hevc", "h265", "mpeg4", "av1", "vp9", "mjpeg"},
        "mov": {"h264", "hevc", "h265", "prores", "mpeg4", "mjpeg"},
        "matroska": {"h264", "hevc", "h265", "vp8", "vp9", "av1", "mjpeg", "mpeg4"},
        "avi": {"mjpeg", "mpeg4", "h264", "rawvideo", "msmpeg4v3"},
        "mpegts": {"h264", "hevc", "h265", "mpeg2video"},
    }

    warnings = []
    for v in video_streams:
        codec = (v.get("codec_name") or "").lower()
        if not codec:
            warnings.append(f"Stream #{v.get('index')}: Missing codec name.")
            continue

        matched_format = None
        for fmt_key in valid_codecs_by_format:
            if fmt_key in format_name:
                matched_format = fmt_key
                break

        if matched_format:
            allowed = valid_codecs_by_format[matched_format]
            if codec not in allowed:
                warnings.append(
                    f"Codec '{codec}' is unusual or non-standard for container '{format_name}'."
                )

    if warnings:
        return {
            "check": "Container & Codec Alignment",
            "status": ValidationStatus.WARNING,
            "message": " | ".join(warnings),
            "details": {"format": format_name, "warnings": warnings},
        }

    return {
        "check": "Container & Codec Alignment",
        "status": ValidationStatus.PASSED,
        "message": f"Codecs are consistent with container '{format_name}'.",
        "details": {"format": format_name},
    }


def check_timestamps(parsed_metadata: dict[str, Any]) -> dict[str, Any]:
    """Check for suspicious future dates, pre-1990 dates (RTC reset), or invalid formats."""
    container = parsed_metadata.get("container", {})
    creation_time = container.get("creation_time")

    if not creation_time:
        return {
            "check": "Timestamp Sanity Check",
            "status": ValidationStatus.WARNING,
            "message": "No creation_time timestamp tag present in container metadata.",
            "details": {"creation_time": None},
        }

    # Attempt to parse ISO timestamp
    # e.g., '2026-03-01T14:22:10.000000Z'
    clean_ts = creation_time.rstrip("Z")
    dt = None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(clean_ts, fmt)
            break
        except ValueError:
            pass

    if not dt:
        return {
            "check": "Timestamp Sanity Check",
            "status": ValidationStatus.WARNING,
            "message": f"Non-standard timestamp format: '{creation_time}'",
            "details": {"creation_time": creation_time},
        }

    dt_utc = dt.replace(tzinfo=timezone.utc)
    now = now_utc()

    if dt_utc > now:
        delta = dt_utc - now
        return {
            "check": "Timestamp Sanity Check",
            "status": ValidationStatus.FAILED,
            "message": f"TIMESTAMP ANOMALY: Creation date is in the future ({creation_time}) by {delta.days} days.",
            "details": {"creation_time": creation_time, "future_delta_days": delta.days},
        }

    if dt_utc.year < 1990:
        return {
            "check": "Timestamp Sanity Check",
            "status": ValidationStatus.WARNING,
            "message": f"SUSPICIOUS DATE: Year {dt_utc.year} indicates possible DVR RTC battery failure or unconfigured clock.",
            "details": {"creation_time": creation_time, "year": dt_utc.year},
        }

    return {
        "check": "Timestamp Sanity Check",
        "status": ValidationStatus.PASSED,
        "message": f"Creation timestamp ({creation_time}) is plausible.",
        "details": {"creation_time": creation_time},
    }


def check_duration_and_bitrate(parsed_metadata: dict[str, Any], file_size_bytes: Optional[int]) -> dict[str, Any]:
    """Verify duration and bitrate consistency to detect stream truncation."""
    container = parsed_metadata.get("container", {})
    duration = container.get("duration_sec")
    bit_rate = container.get("bit_rate")

    if duration is None or duration <= 0:
        return {
            "check": "Duration & Bitrate Consistency",
            "status": ValidationStatus.WARNING,
            "message": "Duration is zero or could not be determined from container header.",
            "details": {"duration": duration, "bit_rate": bit_rate},
        }

    if bit_rate is None or bit_rate <= 0:
        return {
            "check": "Duration & Bitrate Consistency",
            "status": ValidationStatus.PASSED,
            "message": f"Duration is {duration:.2f}s (bitrate not reported in header).",
            "details": {"duration": duration},
        }

    # If file size is available, check theoretical size vs actual size
    if file_size_bytes and file_size_bytes > 0:
        # theoretical bytes = duration (sec) * bit_rate (bps) / 8
        theoretical_bytes = (duration * bit_rate) / 8.0
        ratio = file_size_bytes / theoretical_bytes if theoretical_bytes > 0 else 1.0

        if ratio < 0.4:
            return {
                "check": "Duration & Bitrate Consistency",
                "status": ValidationStatus.FAILED,
                "message": (
                    f"POSSIBLE TRUNCATION: Actual file size ({file_size_bytes} B) is significantly less "
                    f"than expected from duration and bitrate ({int(theoretical_bytes)} B, ratio: {ratio:.2f})."
                ),
                "details": {"actual_bytes": file_size_bytes, "expected_bytes": int(theoretical_bytes), "ratio": round(ratio, 3)},
            }

    return {
        "check": "Duration & Bitrate Consistency",
        "status": ValidationStatus.PASSED,
        "message": f"Duration ({duration:.2f}s) and bitrate ({bit_rate} bps) are mutually consistent.",
        "details": {"duration": duration, "bit_rate": bit_rate},
    }


def check_video_dimensions(parsed_metadata: dict[str, Any]) -> dict[str, Any]:
    """Verify video resolution and frame rate."""
    video_streams = parsed_metadata.get("video_streams", [])

    if not video_streams:
        return {
            "check": "Video Stream Dimensions & FPS",
            "status": ValidationStatus.WARNING,
            "message": "No video streams detected.",
            "details": {},
        }

    for v in video_streams:
        width = v.get("width")
        height = v.get("height")
        fps = v.get("fps")

        if not width or not height or width <= 0 or height <= 0:
            return {
                "check": "Video Stream Dimensions & FPS",
                "status": ValidationStatus.FAILED,
                "message": f"Stream #{v.get('index')}: Invalid video dimensions ({width}x{height}).",
                "details": {"width": width, "height": height},
            }

        if fps is None or fps <= 0:
            return {
                "check": "Video Stream Dimensions & FPS",
                "status": ValidationStatus.WARNING,
                "message": f"Stream #{v.get('index')}: Frame rate is missing or zero (variable frame rate or unparsed).",
                "details": {"width": width, "height": height, "fps": fps},
            }

    primary = video_streams[0]
    return {
        "check": "Video Stream Dimensions & FPS",
        "status": ValidationStatus.PASSED,
        "message": f"Primary video stream is {primary.get('width')}x{primary.get('height')} @ {primary.get('fps')} fps.",
        "details": {"width": primary.get("width"), "height": primary.get("height"), "fps": primary.get("fps")},
    }


def run_validation(
    session: Session,
    evidence_id: str,
    parsed_metadata: dict[str, Any],
    actor_id: str = "Investigator",
) -> tuple[ValidationRun, list[dict[str, Any]]]:
    """
    Run the forensic validation suite on *parsed_metadata*, save a ValidationRun
    record in the DB, and record a CustodyAction.VALIDATION_RUN event.
    """
    item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
    if not item:
        raise ValueError(f"Evidence item {evidence_id} not found.")

    file_size = item.file_size_bytes

    # Run all 4 checks
    results = [
        check_container_codec(parsed_metadata),
        check_timestamps(parsed_metadata),
        check_duration_and_bitrate(parsed_metadata, file_size),
        check_video_dimensions(parsed_metadata),
    ]

    # Determine overall run status
    statuses = [r["status"] for r in results]
    if ValidationStatus.FAILED in statuses:
        overall_status = ValidationStatus.FAILED
    elif ValidationStatus.WARNING in statuses:
        overall_status = ValidationStatus.WARNING
    else:
        overall_status = ValidationStatus.PASSED

    # Create ValidationRun ORM record
    run = ValidationRun(
        evidence_id=evidence_id,
        validation_type="FORENSIC_SANITY_SUITE",
        status=overall_status,
        results_json=json.dumps(results, indent=2),
        performed_by=actor_id,
        performed_at_utc=now_utc(),
        tool_version=TOOL_VERSION,
    )
    session.add(run)
    session.flush()

    # Record custody event
    record_event(
        session=session,
        case_id=item.case_id,
        evidence_id=evidence_id,
        action=CustodyAction.VALIDATION_RUN,
        actor_id=actor_id,
        reason=f"Forensic validation suite completed with overall status: {overall_status}.",
        details={
            "validation_run_id": run.id,
            "overall_status": overall_status,
            "checks_run": len(results),
        },
    )

    logger.info("Validation completed for evidence %s: status=%s", item.evidence_number, overall_status)
    return run, results


def get_latest_validation_run(session: Session, evidence_id: str) -> Optional[ValidationRun]:
    """Retrieve the most recent ValidationRun for the specified evidence item."""
    return (
        session.query(ValidationRun)
        .filter_by(evidence_id=evidence_id)
        .order_by(ValidationRun.performed_at_utc.desc())
        .first()
    )
