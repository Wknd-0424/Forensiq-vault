"""
forensiq/services/timeline_service.py
--------------------------------------
Forensic Timeline Event Management and Timestamp Normalization Service.

Key Principles:
- Raw timestamps are preserved verbatim without modification.
- Normalized UTC timestamps are calculated derived values.
- Timestamp normalization (offsets, drift corrections) logs a
  TIMESTAMP_NORMALIZATION_APPLIED custody event into the hash chain.
- Multi-camera events and segments are correlated chronologically.
- Temporal gaps and footage discontinuities are detected automatically.

Phase 5: Fully implemented.
"""

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from forensiq.constants import (
    AnalystStatus,
    CustodyAction,
    NormalizationMethod,
    TimelineEventType,
)
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.services.custody_service import record_event
from forensiq.utils.canonical_json import canonical_dumps
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helper parsing functions
# ─────────────────────────────────────────────────────────────────────────────

def parse_iso_or_standard_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse various DVR/ISO timestamp formats into a UTC datetime object."""
    if not ts_str or ts_str.strip() in ("", "—", "None", "Unknown", "Not Present"):
        return None

    clean = ts_str.strip().rstrip("Z")
    formats = (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y%m%d_%H%M%S",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(clean, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Video Segment Management
# ─────────────────────────────────────────────────────────────────────────────

def create_or_update_segment_from_evidence(
    session: Session,
    evidence_id: str,
    channel_id: str = "CH-01",
) -> VideoSegment:
    """
    Ensure a primary VideoSegment exists for *evidence_id*, deriving its duration,
    creation time, and codec parameters from extracted MetadataRecord rows.
    """
    item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
    if not item:
        raise ValueError(f"Evidence item not found: {evidence_id}")

    # Check for existing segment
    segment = (
        session.query(VideoSegment)
        .filter_by(evidence_id=evidence_id, channel_id=channel_id)
        .first()
    )
    if not segment:
        segment = VideoSegment(
            evidence_id=evidence_id,
            channel_id=channel_id,
            source_start_offset=0.0,
            parse_status="PARSED",
        )
        session.add(segment)

    # Populate properties from metadata
    meta_records = session.query(MetadataRecord).filter_by(evidence_id=evidence_id).all()
    meta_map = {f"{r.namespace}:{r.key}": r.raw_value for r in meta_records}

    # Container duration
    dur_str = meta_map.get("format:duration")
    duration_sec = 0.0
    if dur_str:
        try:
            duration_sec = float(dur_str)
            segment.duration_seconds = duration_sec
            segment.source_end_offset = duration_sec
        except (ValueError, TypeError):
            pass

    # Creation time
    creation_time = meta_map.get("format:creation_time")
    if creation_time:
        segment.raw_start_time = creation_time
        dt = parse_iso_or_standard_datetime(creation_time)
        if dt:
            segment.normalized_start_utc = dt
            if duration_sec > 0:
                end_dt = dt + timedelta(seconds=duration_sec)
                segment.normalized_end_utc = end_dt
                segment.raw_end_time = to_iso8601(end_dt)

    # Codec, resolution, fps
    segment.codec = meta_map.get("video:0:codec_name") or meta_map.get("format:format_name")
    segment.resolution = meta_map.get("video:0:resolution")
    segment.frame_rate = meta_map.get("video:0:fps")

    session.flush()

    # Automatically create a corresponding METADATA timeline event if not present
    existing_event = (
        session.query(TimelineEvent)
        .filter_by(evidence_id=evidence_id, segment_id=segment.id, event_type=TimelineEventType.METADATA.value)
        .first()
    )
    if not existing_event:
        create_timeline_event(
            session=session,
            case_id=item.case_id,
            event_type=TimelineEventType.METADATA.value,
            raw_timestamp=segment.raw_start_time,
            normalized_utc=segment.normalized_start_utc,
            description=f"Evidence segment start: {item.source_filename} [{segment.channel_id}] ({segment.codec}, {segment.resolution or 'N/A'})",
            evidence_id=evidence_id,
            segment_id=segment.id,
            confidence="HIGH",
        )

    logger.info("VideoSegment initialized for evidence %s (%s)", item.evidence_number, segment.id)
    return segment


def get_segments_for_case(session: Session, case_id: str) -> list[VideoSegment]:
    """Retrieve all video segments associated with evidence items in a case."""
    return (
        session.query(VideoSegment)
        .join(EvidenceItem, VideoSegment.evidence_id == EvidenceItem.id)
        .filter(EvidenceItem.case_id == case_id)
        .order_by(VideoSegment.normalized_start_utc.asc().nulls_last())
        .all()
    )


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp Normalization Engine
# ─────────────────────────────────────────────────────────────────────────────

def apply_timestamp_normalization(
    session: Session,
    evidence_id: str,
    offset_seconds: float,
    method: str = NormalizationMethod.ANALYST_OFFSET.value,
    uncertainty_ms: float = 500.0,
    actor_id: str = "Investigator",
    reason: Optional[str] = None,
) -> list[TimelineEvent]:
    """
    Apply a time offset (drift or timezone adjustment) to all segments and timeline
    events of an evidence item.

    Forensic Invariants:
    - Preserves raw_timestamp exactly as captured.
    - Shifts normalized_timestamp_utc by *offset_seconds*.
    - Records NormalizationMethod and uncertainty.
    - Logs a TIMESTAMP_NORMALIZATION_APPLIED event into the cryptographic custody ledger.
    """
    item = session.query(EvidenceItem).filter_by(id=evidence_id).first()
    if not item:
        raise ValueError(f"Evidence item not found: {evidence_id}")

    delta = timedelta(seconds=offset_seconds)

    # 1. Update all VideoSegments for this evidence item
    segments = session.query(VideoSegment).filter_by(evidence_id=evidence_id).all()
    for seg in segments:
        if seg.raw_start_time:
            base_dt = parse_iso_or_standard_datetime(seg.raw_start_time)
            if base_dt:
                seg.normalized_start_utc = base_dt + delta
                if seg.duration_seconds:
                    seg.normalized_end_utc = seg.normalized_start_utc + timedelta(seconds=seg.duration_seconds)
        seg.timestamp_uncertainty_ms = uncertainty_ms

    # 2. Update all TimelineEvents for this evidence item
    events = session.query(TimelineEvent).filter_by(evidence_id=evidence_id).all()
    for ev in events:
        if ev.raw_timestamp:
            base_dt = parse_iso_or_standard_datetime(ev.raw_timestamp)
            if base_dt:
                ev.normalized_timestamp_utc = base_dt + delta
        ev.offset_seconds = offset_seconds
        ev.normalization_method = method
        ev.uncertainty_ms = uncertainty_ms

    session.flush()

    # 3. Record custody event
    sign = "+" if offset_seconds >= 0 else ""
    desc_reason = reason or f"Applied {sign}{offset_seconds:.1f}s offset ({method}) to evidence {item.evidence_number}"

    record_event(
        session=session,
        case_id=item.case_id,
        evidence_id=evidence_id,
        action=CustodyAction.TIMESTAMP_NORMALIZATION_APPLIED,
        actor_id=actor_id,
        reason=desc_reason,
        details={
            "evidence_id": evidence_id,
            "evidence_number": item.evidence_number,
            "offset_seconds": offset_seconds,
            "normalization_method": method,
            "uncertainty_ms": uncertainty_ms,
            "affected_segments": len(segments),
            "affected_events": len(events),
        },
    )

    logger.info("Applied timestamp normalization (offset=%s%.1fs) on evidence %s", sign, offset_seconds, item.evidence_number)
    return events


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Event CRUD & Querying
# ─────────────────────────────────────────────────────────────────────────────

def create_timeline_event(
    session: Session,
    case_id: str,
    event_type: str,
    raw_timestamp: Optional[str] = None,
    normalized_utc: Optional[datetime] = None,
    description: Optional[str] = None,
    evidence_id: Optional[str] = None,
    segment_id: Optional[str] = None,
    offset_seconds: float = 0.0,
    normalization_method: str = NormalizationMethod.NONE.value,
    confidence: str = "HIGH",
    analyst_status: str = AnalystStatus.PENDING.value,
) -> TimelineEvent:
    """Create and persist a new TimelineEvent record."""
    if not normalized_utc and raw_timestamp:
        normalized_utc = parse_iso_or_standard_datetime(raw_timestamp)

    ev = TimelineEvent(
        case_id=case_id,
        evidence_id=evidence_id,
        segment_id=segment_id,
        event_type=event_type,
        raw_timestamp=raw_timestamp,
        normalized_timestamp_utc=normalized_utc,
        offset_seconds=offset_seconds,
        normalization_method=normalization_method,
        confidence=confidence,
        analyst_status=analyst_status,
        description=description,
    )
    session.add(ev)
    session.flush()
    return ev


def get_case_timeline(session: Session, case_id: str) -> list[TimelineEvent]:
    """
    Retrieve all timeline events for *case_id*, sorted chronologically by normalized_timestamp_utc.
    Events without normalized timestamps are placed at the end.
    """
    return (
        session.query(TimelineEvent)
        .filter_by(case_id=case_id)
        .order_by(TimelineEvent.normalized_timestamp_utc.asc().nulls_last(), TimelineEvent.raw_timestamp.asc())
        .all()
    )


def update_event_analyst_status(
    session: Session,
    event_id: str,
    status: str,
    actor_id: str = "Investigator",
    notes: Optional[str] = None,
) -> TimelineEvent:
    """Update analyst review status (PENDING, CONFIRMED, REJECTED) on a timeline event."""
    ev = session.query(TimelineEvent).filter_by(id=event_id).first()
    if not ev:
        raise ValueError(f"Timeline event not found: {event_id}")

    ev.analyst_status = status
    if notes:
        ev.description = f"{ev.description or ''}\n[Review by {actor_id}]: {notes}".strip()

    session.flush()
    return ev


# ─────────────────────────────────────────────────────────────────────────────
# Forensic Gap & Discontinuity Analysis
# ─────────────────────────────────────────────────────────────────────────────

def detect_timeline_gaps(
    events: list[TimelineEvent],
    threshold_seconds: float = 120.0,
) -> list[dict[str, Any]]:
    """
    Analyze sorted timeline events to detect temporal footage gaps or clock anomalies.
    Returns a list of detected gap descriptors.
    """
    gaps: list[dict[str, Any]] = []
    timed_events = [e for e in events if e.normalized_timestamp_utc is not None]

    for i in range(len(timed_events) - 1):
        curr_ev = timed_events[i]
        next_ev = timed_events[i + 1]

        t1 = curr_ev.normalized_timestamp_utc
        t2 = next_ev.normalized_timestamp_utc

        diff = (t2 - t1).total_seconds()
        if diff > threshold_seconds:
            gaps.append({
                "type": "TEMPORAL_GAP",
                "start_utc": to_iso8601(t1),
                "end_utc": to_iso8601(t2),
                "gap_duration_seconds": round(diff, 2),
                "before_event_id": curr_ev.id,
                "after_event_id": next_ev.id,
                "description": (
                    f"Temporal gap of {diff:.1f} seconds ({diff / 60:.1f} min) "
                    f"detected between events {curr_ev.event_type} and {next_ev.event_type}."
                ),
            })
        elif diff < 0:
            gaps.append({
                "type": "TIME_REVERSAL_ANOMALY",
                "start_utc": to_iso8601(t1),
                "end_utc": to_iso8601(t2),
                "gap_duration_seconds": round(diff, 2),
                "before_event_id": curr_ev.id,
                "after_event_id": next_ev.id,
                "description": (
                    f"CHRONOLOGY REVERSAL: Event {next_ev.event_type} occurs {abs(diff):.1f}s "
                    f"before previous event {curr_ev.event_type}."
                ),
            })

    return gaps


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Camera Event Correlation Engine
# ─────────────────────────────────────────────────────────────────────────────

def extract_event_entity_class(description: Optional[str]) -> str:
    """
    Extract and normalize the entity/activity class from an event description.
    Maps fine-grained detector classes to canonical surveillance categories:
      - person / pedestrian -> 'person'
      - car / truck / bus / motorcycle / vehicle -> 'vehicle'
      - motion / environmental -> 'motion'
      - scene_change / tamper -> 'scene_change'
      - anomaly -> 'anomaly'
    Returns canonical class name or 'other' if unclassified.
    """
    if not description:
        return "other"

    desc_lower = description.lower()

    # Pattern: AI Detection: <class> (<conf>)
    if "ai detection:" in desc_lower:
        part = desc_lower.split("ai detection:", 1)[1].strip()
        tokens = part.split()
        if tokens:
            candidate = tokens[0].strip("():,")
            if candidate in ("person", "pedestrian"):
                return "person"
            if candidate in ("car", "motorcycle", "bus", "truck", "vehicle"):
                return "vehicle"
            if candidate in ("motion", "scene_change", "anomaly"):
                return candidate

    # Fallback keyword scanning
    if any(k in desc_lower for k in ("person", "pedestrian", "subject", "suspect")):
        return "person"
    if any(k in desc_lower for k in ("car", "vehicle", "truck", "motorcycle", "bus", "auto", "license")):
        return "vehicle"
    if "scene_change" in desc_lower or "scene change" in desc_lower or "tamper" in desc_lower:
        return "scene_change"
    if "anomaly" in desc_lower or "outlier" in desc_lower:
        return "anomaly"
    if "motion" in desc_lower:
        return "motion"

    return "other"


def correlate_cross_camera_events(
    events: list[TimelineEvent],
    time_window_seconds: float = 30.0,
    camera_map: Optional[dict[str, str]] = None,
) -> list[dict[str, Any]]:
    """
    Correlate detected surveillance events across multiple cameras within a configurable time window.

    Algorithm:
    1. Filter events with valid normalized UTC timestamps.
    2. Map each event to its camera identifier (using camera_map, segment_id, or evidence_id).
    3. Categorize each event into its canonical entity type (person, vehicle, motion, etc.).
    4. Group matching entity events occurring within *time_window_seconds* of each other.
    5. Filter out single-camera-only groups: only retain clusters spanning >= 2 distinct cameras.

    Returns a list of cross-camera correlation groups sorted chronologically.
    """
    camera_map = camera_map or {}
    timed_events: list[tuple[TimelineEvent, str, str]] = []

    for ev in events:
        if ev.normalized_timestamp_utc is None:
            continue
        cam = camera_map.get(ev.evidence_id, ev.evidence_id or ev.segment_id or "Camera-Unknown")
        entity = extract_event_entity_class(ev.description)
        timed_events.append((ev, cam, entity))

    if not timed_events:
        return []

    # Sort all timed events by timestamp
    timed_events.sort(key=lambda item: item[0].normalized_timestamp_utc)

    # Group by entity type first
    by_entity: dict[str, list[tuple[TimelineEvent, str, str]]] = {}
    for item in timed_events:
        ent = item[2]
        by_entity.setdefault(ent, []).append(item)

    correlations: list[dict[str, Any]] = []
    corr_idx = 1

    for entity, ent_events in by_entity.items():
        if len(ent_events) < 2:
            continue

        # Cluster events within the time window
        clusters: list[list[tuple[TimelineEvent, str, str]]] = []
        current_cluster: list[tuple[TimelineEvent, str, str]] = [ent_events[0]]

        for i in range(1, len(ent_events)):
            curr_ev = ent_events[i]
            prev_ev = current_cluster[-1]
            diff = (curr_ev[0].normalized_timestamp_utc - prev_ev[0].normalized_timestamp_utc).total_seconds()

            if diff <= time_window_seconds:
                current_cluster.append(curr_ev)
            else:
                clusters.append(current_cluster)
                current_cluster = [curr_ev]

        if current_cluster:
            clusters.append(current_cluster)

        # Retain only clusters that span >= 2 distinct cameras
        for cluster in clusters:
            cams_in_cluster = {c for _, c, _ in cluster}
            if len(cams_in_cluster) >= 2:
                start_dt = cluster[0][0].normalized_timestamp_utc
                end_dt = cluster[-1][0].normalized_timestamp_utc
                span = (end_dt - start_dt).total_seconds()

                cluster_events_data = []
                for ev, cam, _ in cluster:
                    cluster_events_data.append({
                        "event_id": ev.id,
                        "camera": cam,
                        "evidence_id": ev.evidence_id,
                        "segment_id": ev.segment_id,
                        "timestamp_utc": to_iso8601(ev.normalized_timestamp_utc),
                        "raw_timestamp": ev.raw_timestamp or "—",
                        "confidence": ev.confidence or "HIGH",
                        "analyst_status": ev.analyst_status,
                        "description": ev.description or "",
                    })

                cam_names = sorted(list(cams_in_cluster))
                correlations.append({
                    "correlation_id": f"CORR-{corr_idx:04d}",
                    "entity_type": entity,
                    "start_time_utc": to_iso8601(start_dt),
                    "end_time_utc": to_iso8601(end_dt),
                    "time_span_seconds": round(span, 2),
                    "time_window_seconds": time_window_seconds,
                    "camera_count": len(cams_in_cluster),
                    "cameras": cam_names,
                    "event_count": len(cluster),
                    "events": cluster_events_data,
                    "description": (
                        f"Cross-Camera {entity.upper()} event correlated across {len(cams_in_cluster)} cameras "
                        f"({', '.join(cam_names)}) within {span:.1f}s (window: {time_window_seconds:.0f}s)"
                    ),
                })
                corr_idx += 1

    # Sort all correlations chronologically by start_time_utc
    correlations.sort(key=lambda c: c["start_time_utc"])
    return correlations


def get_case_cross_camera_correlations(
    session: Session,
    case_id: str,
    time_window_seconds: float = 30.0,
) -> list[dict[str, Any]]:
    """
    Retrieve and correlate cross-camera events for an entire case.
    Resolves human-readable camera labels from EvidenceItem records.
    """
    events = (
        session.query(TimelineEvent)
        .filter_by(case_id=case_id)
        .order_by(TimelineEvent.normalized_timestamp_utc.asc().nulls_last())
        .all()
    )

    evidence_items = session.query(EvidenceItem).filter_by(case_id=case_id).all()
    camera_map = {}
    for item in evidence_items:
        label = item.evidence_number or item.source_filename
        camera_map[item.id] = label

    return correlate_cross_camera_events(events, time_window_seconds=time_window_seconds, camera_map=camera_map)


# ─────────────────────────────────────────────────────────────────────────────
# Exports (JSON & CSV)
# ─────────────────────────────────────────────────────────────────────────────

def export_timeline_json(session: Session, case_id: str) -> str:
    """Export all case timeline events as structured canonical JSON."""
    events = get_case_timeline(session, case_id)
    items_list = []
    for ev in events:
        items_list.append({
            "event_id": ev.id,
            "event_type": ev.event_type,
            "evidence_id": ev.evidence_id,
            "segment_id": ev.segment_id,
            "raw_timestamp": ev.raw_timestamp,
            "normalized_timestamp_utc": to_iso8601(ev.normalized_timestamp_utc),
            "offset_seconds": ev.offset_seconds,
            "normalization_method": ev.normalization_method,
            "confidence": ev.confidence,
            "analyst_status": ev.analyst_status,
            "description": ev.description,
        })

    payload = {
        "case_id": case_id,
        "exported_at_utc": to_iso8601(now_utc()),
        "total_events": len(items_list),
        "events": items_list,
    }
    return canonical_dumps(payload)


def export_timeline_csv(session: Session, case_id: str) -> str:
    """Export all case timeline events formatted as RFC 4180 CSV."""
    events = get_case_timeline(session, case_id)
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    writer.writerow([
        "Event ID",
        "Normalized UTC",
        "Raw Timestamp",
        "Offset (s)",
        "Normalization Method",
        "Event Type",
        "Confidence",
        "Analyst Status",
        "Evidence ID",
        "Description",
    ])

    for ev in events:
        writer.writerow([
            ev.id,
            to_iso8601(ev.normalized_timestamp_utc) or "",
            ev.raw_timestamp or "",
            f"{ev.offset_seconds:.1f}" if ev.offset_seconds is not None else "0.0",
            ev.normalization_method or "NONE",
            ev.event_type,
            ev.confidence or "HIGH",
            ev.analyst_status,
            ev.evidence_id or "",
            (ev.description or "").replace("\n", " "),
        ])

    return output.getvalue()
