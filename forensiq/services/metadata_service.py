"""
forensiq/services/metadata_service.py
--------------------------------------
Video and audio metadata extraction service using ffprobe.

Adheres strictly to forensic principles:
- Only runs on verified working copies.
- Raw values extracted from ffprobe are preserved exactly as returned.
- Normalized values are stored alongside raw values without overwriting them.
- No invented metadata: missing or unparseable fields are recorded as None or "Unknown".
- If ffprobe is missing or fails, raises MetadataExtractionError without crashing the application.
- Persisting metadata automatically records a METADATA_EXTRACTED custody event.

Phase 4: Fully implemented.
"""

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

import forensiq.config as _cfg
from forensiq.constants import CustodyAction
from forensiq.models.metadata import MetadataRecord
from forensiq.services.custody_service import record_event

logger = logging.getLogger(__name__)


class MetadataExtractionError(Exception):
    """Raised when metadata extraction via ffprobe fails or tool is unavailable."""


def is_ffprobe_available() -> bool:
    """Return True if ffprobe binary is found on PATH or via configured FFPROBE_PATH."""
    probe_path = getattr(_cfg, "FFPROBE_PATH", "ffprobe")
    if Path(probe_path).is_file():
        return True
    return shutil.which(probe_path) is not None


def get_ffprobe_command() -> str:
    """Return the resolved executable command or path for ffprobe."""
    probe_path = getattr(_cfg, "FFPROBE_PATH", "ffprobe")
    resolved = shutil.which(probe_path)
    return resolved if resolved else probe_path


def run_ffprobe(file_path: Path, timeout: int = 30) -> dict:
    """
    Execute ffprobe against *file_path* and return parsed JSON.

    Parameters:
        file_path: Absolute or resolved Path to the media file.
        timeout: Maximum execution time in seconds before aborting.

    Returns:
        dict: Parsed JSON containing 'format' and 'streams'.
    """
    if not is_ffprobe_available():
        raise MetadataExtractionError(
            "ffprobe executable not found. Please install FFmpeg or configure "
            "FFPROBE_PATH in the application environment."
        )

    cmd = [
        get_ffprobe_command(),
        "-v", "error",
        "-show_format",
        "-show_streams",
        "-print_format", "json",
        str(file_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MetadataExtractionError(
            f"ffprobe execution timed out after {timeout} seconds on {file_path.name}"
        ) from exc
    except Exception as exc:
        raise MetadataExtractionError(
            f"Failed to execute ffprobe: {exc}"
        ) from exc

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or f"Process exited with code {proc.returncode}"
        raise MetadataExtractionError(f"ffprobe failed: {err_msg}")

    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            raise MetadataExtractionError("ffprobe output is not a JSON dictionary.")
        return data
    except json.JSONDecodeError as exc:
        raise MetadataExtractionError(
            f"ffprobe returned invalid JSON output: {exc}"
        ) from exc


def _parse_frame_rate(rate_str: Optional[str]) -> Optional[float]:
    """Parse '25/1' or '30000/1001' into float FPS, or None if invalid."""
    if not rate_str or rate_str == "0/0":
        return None
    try:
        if "/" in rate_str:
            num, den = rate_str.split("/", 1)
            den_f = float(den)
            return round(float(num) / den_f, 3) if den_f != 0 else None
        return round(float(rate_str), 3)
    except (ValueError, ZeroDivisionError):
        return None


def _format_duration(seconds_val: Optional[float]) -> Optional[str]:
    """Convert float seconds into HH:MM:SS.mmm format."""
    if seconds_val is None:
        return None
    try:
        total_sec = float(seconds_val)
        hours = int(total_sec // 3600)
        minutes = int((total_sec % 3600) // 60)
        secs = total_sec % 60
        return f"{hours:02d}:{minutes:02d}:{secs:06.3f}"
    except (ValueError, TypeError):
        return None


def parse_metadata(raw_data: dict) -> dict[str, Any]:
    """
    Parse raw ffprobe JSON dictionary into structured categories.
    Never invents data: missing items remain None.
    """
    format_info = raw_data.get("format", {})
    streams = raw_data.get("streams", [])

    duration_sec = None
    if "duration" in format_info:
        try:
            duration_sec = float(format_info["duration"])
        except (ValueError, TypeError):
            pass

    size_bytes = None
    if "size" in format_info:
        try:
            size_bytes = int(format_info["size"])
        except (ValueError, TypeError):
            pass

    bit_rate = None
    if "bit_rate" in format_info:
        try:
            bit_rate = int(format_info["bit_rate"])
        except (ValueError, TypeError):
            pass

    tags = format_info.get("tags", {})
    creation_time = tags.get("creation_time")

    container = {
        "format_name": format_info.get("format_name"),
        "format_long_name": format_info.get("format_long_name"),
        "duration_sec": duration_sec,
        "duration_formatted": _format_duration(duration_sec),
        "size_bytes": size_bytes,
        "bit_rate": bit_rate,
        "start_time": format_info.get("start_time"),
        "creation_time": creation_time,
        "tags": tags,
    }

    video_streams = []
    audio_streams = []
    other_streams = []

    for stream in streams:
        codec_type = stream.get("codec_type")
        if codec_type == "video":
            fps = _parse_frame_rate(stream.get("r_frame_rate")) or _parse_frame_rate(stream.get("avg_frame_rate"))
            nb_frames = None
            if "nb_frames" in stream:
                try:
                    nb_frames = int(stream["nb_frames"])
                except (ValueError, TypeError):
                    pass

            v_bit_rate = None
            if "bit_rate" in stream:
                try:
                    v_bit_rate = int(stream["bit_rate"])
                except (ValueError, TypeError):
                    pass

            video_streams.append({
                "index": stream.get("index"),
                "codec_name": stream.get("codec_name"),
                "codec_long_name": stream.get("codec_long_name"),
                "profile": stream.get("profile"),
                "width": stream.get("width"),
                "height": stream.get("height"),
                "resolution": f"{stream.get('width')}x{stream.get('height')}" if stream.get("width") and stream.get("height") else None,
                "aspect_ratio": stream.get("display_aspect_ratio"),
                "pix_fmt": stream.get("pix_fmt"),
                "fps": fps,
                "r_frame_rate": stream.get("r_frame_rate"),
                "avg_frame_rate": stream.get("avg_frame_rate"),
                "nb_frames": nb_frames,
                "bit_rate": v_bit_rate,
                "color_space": stream.get("color_space"),
                "tags": stream.get("tags", {}),
            })
        elif codec_type == "audio":
            sample_rate = None
            if "sample_rate" in stream:
                try:
                    sample_rate = int(stream["sample_rate"])
                except (ValueError, TypeError):
                    pass

            a_bit_rate = None
            if "bit_rate" in stream:
                try:
                    a_bit_rate = int(stream["bit_rate"])
                except (ValueError, TypeError):
                    pass

            audio_streams.append({
                "index": stream.get("index"),
                "codec_name": stream.get("codec_name"),
                "codec_long_name": stream.get("codec_long_name"),
                "channels": stream.get("channels"),
                "channel_layout": stream.get("channel_layout"),
                "sample_rate": sample_rate,
                "bit_rate": a_bit_rate,
                "tags": stream.get("tags", {}),
            })
        else:
            other_streams.append({
                "index": stream.get("index"),
                "codec_type": codec_type,
                "codec_name": stream.get("codec_name"),
            })

    return {
        "container": container,
        "video_streams": video_streams,
        "audio_streams": audio_streams,
        "other_streams": other_streams,
        "raw_ffprobe": raw_data,
    }


def persist_metadata(
    session: Session,
    evidence_id: str,
    case_id: str,
    parsed_metadata: dict[str, Any],
    actor_id: str = "System",
) -> list[MetadataRecord]:
    """
    Persist structured metadata as individual MetadataRecord rows in the DB.
    Deletes any prior metadata records for this evidence item before inserting new ones.
    Records a CustodyAction.METADATA_EXTRACTED custody event.
    """
    # Remove prior records for idempotence
    session.query(MetadataRecord).filter_by(evidence_id=evidence_id).delete()

    records: list[MetadataRecord] = []

    def _add(namespace: str, key: str, raw_val: Any, norm_val: Any = None, warning: Optional[str] = None):
        if raw_val is None and norm_val is None:
            return
        raw_str = str(raw_val) if raw_val is not None else "Not Present"
        norm_str = str(norm_val) if norm_val is not None else raw_str

        rec = MetadataRecord(
            evidence_id=evidence_id,
            namespace=namespace,
            key=key,
            raw_value=raw_str,
            normalized_value=norm_str,
            source_reference="ffprobe",
            confidence="HIGH",
            warning=warning,
        )
        session.add(rec)
        records.append(rec)

    # 1. Container metadata
    container = parsed_metadata.get("container", {})
    _add("format", "format_name", container.get("format_name"))
    _add("format", "format_long_name", container.get("format_long_name"))
    _add("format", "duration", container.get("duration_sec"), container.get("duration_formatted"))
    _add("format", "size_bytes", container.get("size_bytes"))
    _add("format", "bit_rate", container.get("bit_rate"))
    _add("format", "creation_time", container.get("creation_time"))

    # Container tags
    for tag_k, tag_v in container.get("tags", {}).items():
        _add("format_tag", tag_k, tag_v)

    # 2. Video streams
    for v in parsed_metadata.get("video_streams", []):
        ns = f"video:{v.get('index', 0)}"
        _add(ns, "codec_name", v.get("codec_name"))
        _add(ns, "codec_long_name", v.get("codec_long_name"))
        _add(ns, "profile", v.get("profile"))
        _add(ns, "width", v.get("width"))
        _add(ns, "height", v.get("height"))
        _add(ns, "resolution", v.get("resolution"))
        _add(ns, "fps", v.get("r_frame_rate"), v.get("fps"))
        _add(ns, "aspect_ratio", v.get("aspect_ratio"))
        _add(ns, "pix_fmt", v.get("pix_fmt"))
        _add(ns, "nb_frames", v.get("nb_frames"))
        _add(ns, "bit_rate", v.get("bit_rate"))
        _add(ns, "color_space", v.get("color_space"))

    # 3. Audio streams
    for a in parsed_metadata.get("audio_streams", []):
        ns = f"audio:{a.get('index', 0)}"
        _add(ns, "codec_name", a.get("codec_name"))
        _add(ns, "channels", a.get("channels"))
        _add(ns, "channel_layout", a.get("channel_layout"))
        _add(ns, "sample_rate", a.get("sample_rate"), f"{a.get('sample_rate')} Hz" if a.get('sample_rate') else None)
        _add(ns, "bit_rate", a.get("bit_rate"))

    session.flush()

    # Record custody event
    record_event(
        session=session,
        case_id=case_id,
        evidence_id=evidence_id,
        action=CustodyAction.METADATA_EXTRACTED,
        actor_id=actor_id,
        reason=f"Extracted {len(records)} metadata records via ffprobe from working copy.",
        details={
            "tool": "ffprobe",
            "records_count": len(records),
            "format": container.get("format_name"),
            "video_streams": len(parsed_metadata.get("video_streams", [])),
            "audio_streams": len(parsed_metadata.get("audio_streams", [])),
        },
    )

    logger.info("Persisted %d metadata records for evidence %s", len(records), evidence_id)
    return records


def get_metadata_for_evidence(session: Session, evidence_id: str) -> list[MetadataRecord]:
    """Retrieve all stored metadata records for an evidence item."""
    return (
        session.query(MetadataRecord)
        .filter_by(evidence_id=evidence_id)
        .order_by(MetadataRecord.namespace.asc(), MetadataRecord.key.asc())
        .all()
    )


def extract_and_persist_metadata(
    session: Session,
    case_id: str,
    evidence_id: str,
    working_copy_path: Path,
    actor_id: str = "Investigator",
) -> tuple[dict[str, Any], list[MetadataRecord]]:
    """
    High-level orchestrator: runs ffprobe on working_copy_path, parses results,
    and persists MetadataRecord rows with custody logging.
    """
    raw_data = run_ffprobe(working_copy_path)
    parsed = parse_metadata(raw_data)
    records = persist_metadata(
        session=session,
        evidence_id=evidence_id,
        case_id=case_id,
        parsed_metadata=parsed,
        actor_id=actor_id,
    )
    return parsed, records
