"""
tests/test_timeline.py
----------------------
Unit and integration tests for timeline event management, timestamp normalization,
chronological correlation, and gap analysis.

Phase 5: Fully implemented.
"""

from datetime import datetime, timedelta, timezone

import pytest

from forensiq.constants import (
    AnalystStatus,
    CustodyAction,
    NormalizationMethod,
    TimelineEventType,
)
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.services.case_service import create_case
from forensiq.services.timeline_service import (
    apply_timestamp_normalization,
    correlate_cross_camera_events,
    create_or_update_segment_from_evidence,
    create_timeline_event,
    detect_timeline_gaps,
    export_timeline_csv,
    export_timeline_json,
    extract_event_entity_class,
    get_case_cross_camera_correlations,
    get_case_timeline,
    get_segments_for_case,
    parse_iso_or_standard_datetime,
    update_event_analyst_status,
)
from forensiq.utils.utc_utils import now_utc, to_iso8601


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to isolated SQLite."""
    db_url = f"sqlite:///{tmp_path / 'test_timeline.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


@pytest.fixture
def timeline_fixture():
    with session_scope() as session:
        case = create_case(session, "CASE-TIME-001", "Timeline Case", investigator_name="Agent Mulder")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-TIME-01",
            source_filename="bank_cam1.mp4",
            sanitized_filename="bank_cam1.mp4",
            file_size_bytes=10485760,
            imported_by="Agent Mulder",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        # Add some sample metadata records
        session.add(MetadataRecord(
            evidence_id=item.id,
            namespace="format",
            key="duration",
            raw_value="120.5",
            normalized_value="00:02:00.500",
        ))
        session.add(MetadataRecord(
            evidence_id=item.id,
            namespace="format",
            key="creation_time",
            raw_value="2026-03-01T14:00:00Z",
        ))
        session.add(MetadataRecord(
            evidence_id=item.id,
            namespace="video:0",
            key="codec_name",
            raw_value="h264",
        ))
        session.add(MetadataRecord(
            evidence_id=item.id,
            namespace="video:0",
            key="resolution",
            raw_value="1920x1080",
        ))
        session.add(MetadataRecord(
            evidence_id=item.id,
            namespace="video:0",
            key="fps",
            raw_value="25.0",
        ))
        session.flush()

        case_id = case.id
        evidence_id = item.id

    return case_id, evidence_id


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_iso_or_standard_datetime():
    dt = parse_iso_or_standard_datetime("2026-03-01T14:30:00Z")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 3
    assert dt.day == 1
    assert dt.hour == 14
    assert dt.minute == 30

    dt2 = parse_iso_or_standard_datetime("2026-03-01 14:30:00")
    assert dt2 is not None
    assert dt2.hour == 14

    assert parse_iso_or_standard_datetime(None) is None
    assert parse_iso_or_standard_datetime("Not Present") is None
    assert parse_iso_or_standard_datetime("invalid-string") is None


def test_create_or_update_segment_from_evidence(timeline_fixture):
    case_id, evidence_id = timeline_fixture

    with session_scope() as session:
        segment = create_or_update_segment_from_evidence(session, evidence_id, channel_id="CAM-FRONT")

        assert segment.evidence_id == evidence_id
        assert segment.channel_id == "CAM-FRONT"
        assert segment.duration_seconds == 120.5
        assert segment.codec == "h264"
        assert segment.resolution == "1920x1080"
        assert segment.raw_start_time == "2026-03-01T14:00:00Z"
        assert segment.normalized_start_utc is not None
        assert segment.normalized_start_utc.hour == 14

        # Verify automatic METADATA timeline event
        events = session.query(TimelineEvent).filter_by(evidence_id=evidence_id).all()
        assert len(events) >= 1
        meta_ev = events[0]
        assert meta_ev.event_type == TimelineEventType.METADATA.value
        assert "bank_cam1.mp4" in meta_ev.description


def test_apply_timestamp_normalization(timeline_fixture):
    case_id, evidence_id = timeline_fixture

    with session_scope() as session:
        create_or_update_segment_from_evidence(session, evidence_id)

        # Apply +5.5 hours (+19800 seconds) offset (e.g. UTC to IST)
        offset = 19800.0
        events = apply_timestamp_normalization(
            session=session,
            evidence_id=evidence_id,
            offset_seconds=offset,
            method=NormalizationMethod.ANALYST_OFFSET.value,
            actor_id="Analyst Scully",
            reason="Adjusted for local IST timezone",
        )

        assert len(events) >= 1
        ev = events[0]
        assert ev.offset_seconds == offset
        assert ev.normalization_method == NormalizationMethod.ANALYST_OFFSET.value
        # Original raw timestamp must be preserved verbatim!
        assert ev.raw_timestamp == "2026-03-01T14:00:00Z"

        # Normalized timestamp must be shifted by 5.5 hours (14:00 + 5.5 = 19:30)
        assert ev.normalized_timestamp_utc.hour == 19
        assert ev.normalized_timestamp_utc.minute == 30

        # Verify custody event
        custody_ev = (
            session.query(CustodyEvent)
            .filter_by(
                evidence_id=evidence_id,
                action=CustodyAction.TIMESTAMP_NORMALIZATION_APPLIED.value,
            )
            .first()
        )
        assert custody_ev is not None
        assert custody_ev.actor_id == "Analyst Scully"
        assert "Adjusted for local IST" in custody_ev.reason


def test_get_case_timeline_sorting(timeline_fixture):
    case_id, evidence_id = timeline_fixture

    with session_scope() as session:
        t_base = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)

        # Add 3 events in jumbled order
        create_timeline_event(session, case_id, "METADATA", normalized_utc=t_base + timedelta(minutes=15), description="Event C")
        create_timeline_event(session, case_id, "AI_PRELIMINARY", normalized_utc=t_base, description="Event A")
        create_timeline_event(session, case_id, "MANUAL_ENTRY", normalized_utc=t_base + timedelta(minutes=5), description="Event B")

        timeline = get_case_timeline(session, case_id)
        assert len(timeline) == 3
        assert timeline[0].description == "Event A"
        assert timeline[1].description == "Event B"
        assert timeline[2].description == "Event C"


def test_detect_timeline_gaps():
    t_base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Event 1 at 12:00, Event 2 at 12:01 (diff = 60s -> normal)
    # Event 3 at 12:10 (diff = 540s -> gap > threshold 120s)
    # Event 4 at 12:05 (diff = -300s -> chronology reversal anomaly)
    events = [
        TimelineEvent(id="e1", event_type="METADATA", normalized_timestamp_utc=t_base),
        TimelineEvent(id="e2", event_type="METADATA", normalized_timestamp_utc=t_base + timedelta(seconds=60)),
        TimelineEvent(id="e3", event_type="METADATA", normalized_timestamp_utc=t_base + timedelta(seconds=600)),
        TimelineEvent(id="e4", event_type="METADATA", normalized_timestamp_utc=t_base + timedelta(seconds=300)),
    ]

    gaps = detect_timeline_gaps(events, threshold_seconds=120.0)
    assert len(gaps) == 2

    # First is temporal gap
    assert gaps[0]["type"] == "TEMPORAL_GAP"
    assert gaps[0]["gap_duration_seconds"] == 540.0

    # Second is time reversal anomaly
    assert gaps[1]["type"] == "TIME_REVERSAL_ANOMALY"


def test_export_timeline_json_and_csv(timeline_fixture):
    case_id, evidence_id = timeline_fixture

    with session_scope() as session:
        create_timeline_event(session, case_id, "METADATA", raw_timestamp="2026-03-01T10:00:00Z", description="Export test event")

        # JSON Export
        json_str = export_timeline_json(session, case_id)
        assert "events" in json_str
        assert "Export test event" in json_str

        # CSV Export
        csv_str = export_timeline_csv(session, case_id)
        assert "Event ID,Normalized UTC,Raw Timestamp" in csv_str
        assert "Export test event" in csv_str


def test_update_event_analyst_status(timeline_fixture):
    case_id, evidence_id = timeline_fixture

    with session_scope() as session:
        ev = create_timeline_event(session, case_id, "AI_PRELIMINARY", description="Subject detected")
        assert ev.analyst_status == AnalystStatus.PENDING.value

        updated = update_event_analyst_status(session, ev.id, AnalystStatus.CONFIRMED.value, actor_id="Analyst", notes="Confirmed license plate")
        assert updated.analyst_status == AnalystStatus.CONFIRMED.value
        assert "Confirmed license plate" in updated.description


# ─────────────────────────────────────────────────────────────────────────────
# UI Tests for TimelineAIPage & TimelineWidget
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_timeline_widget_scrubbing(qapp):
    from forensiq.ui.widgets.timeline_widget import TimelineWidget

    widget = TimelineWidget()
    widget.set_duration(120.0)

    received_pos = []
    widget.position_changed.connect(lambda p: received_pos.append(p))

    widget._update_position_from_mouse(widget.width() / 2)
    assert len(received_pos) == 1
    assert 50.0 <= received_pos[0] <= 70.0


def test_timeline_ai_page_refresh(qapp, timeline_fixture):
    case_id, evidence_id = timeline_fixture
    from forensiq.ui.pages.timeline_ai_page import TimelineAIPage

    class MockMainWindow:
        active_case_id = case_id
        active_evidence_id = evidence_id
        def set_active_evidence_id(self, ev_id): pass

    mock_mw = MockMainWindow()
    page = TimelineAIPage(main_window=mock_mw)
    page.refresh()

    assert page._evidence_combo.isEnabled()
    assert page._evidence_combo.count() == 1
    assert page._triage_btn.isEnabled()
    assert page._apply_norm_btn.isEnabled()
    assert page._event_table.rowCount() >= 1
    assert hasattr(page, "_corr_table")
    assert hasattr(page, "_corr_window_spin")


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Camera Event Correlation Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_event_entity_class():
    assert extract_event_entity_class("AI Detection: person (0.85)") == "person"
    assert extract_event_entity_class("AI Detection: car (0.78)") == "vehicle"
    assert extract_event_entity_class("AI Detection: motorcycle (0.92)") == "vehicle"
    assert extract_event_entity_class("AI Detection: truck (0.64)") == "vehicle"
    assert extract_event_entity_class("AI Detection: motion (0.70)") == "motion"
    assert extract_event_entity_class("AI Detection: scene_change (0.99)") == "scene_change"
    assert extract_event_entity_class("AI Detection: anomaly (0.81)") == "anomaly"
    assert extract_event_entity_class("Pedestrian walking past gate") == "person"
    assert extract_event_entity_class("Blue vehicle entering parking") == "vehicle"
    assert extract_event_entity_class("Evidence segment start") == "other"
    assert extract_event_entity_class(None) == "other"


def test_correlate_cross_camera_events_within_window():
    t_base = datetime(2026, 3, 1, 10, 30, 0, tzinfo=timezone.utc)

    # Camera 1 detects person at T=0
    # Camera 2 detects person at T=12s
    # Camera 3 detects person at T=25s
    events = [
        TimelineEvent(
            id="ev-1",
            evidence_id="EVD-01",
            description="AI Detection: person (0.85)",
            normalized_timestamp_utc=t_base,
            confidence="HIGH",
            analyst_status="PENDING",
        ),
        TimelineEvent(
            id="ev-2",
            evidence_id="EVD-02",
            description="AI Detection: person (0.88)",
            normalized_timestamp_utc=t_base + timedelta(seconds=12),
            confidence="HIGH",
            analyst_status="PENDING",
        ),
        TimelineEvent(
            id="ev-3",
            evidence_id="EVD-03",
            description="AI Detection: person (0.79)",
            normalized_timestamp_utc=t_base + timedelta(seconds=25),
            confidence="HIGH",
            analyst_status="PENDING",
        ),
    ]

    camera_map = {"EVD-01": "CAM-01-Gate", "EVD-02": "CAM-02-Lobby", "EVD-03": "CAM-03-Hallway"}
    correlations = correlate_cross_camera_events(events, time_window_seconds=30.0, camera_map=camera_map)

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["entity_type"] == "person"
    assert corr["camera_count"] == 3
    assert corr["event_count"] == 3
    assert corr["time_span_seconds"] == 25.0
    assert "CAM-01-Gate" in corr["cameras"]
    assert "CAM-02-Lobby" in corr["cameras"]
    assert "CAM-03-Hallway" in corr["cameras"]


def test_correlate_cross_camera_events_outside_window_separated():
    t_base = datetime(2026, 3, 1, 10, 30, 0, tzinfo=timezone.utc)

    # Camera 1 detects person at T=0
    # Camera 2 detects person at T=90s (diff = 90s > window 30s)
    events = [
        TimelineEvent(
            id="ev-1",
            evidence_id="EVD-01",
            description="AI Detection: person (0.85)",
            normalized_timestamp_utc=t_base,
        ),
        TimelineEvent(
            id="ev-2",
            evidence_id="EVD-02",
            description="AI Detection: person (0.88)",
            normalized_timestamp_utc=t_base + timedelta(seconds=90),
        ),
    ]

    camera_map = {"EVD-01": "CAM-01", "EVD-02": "CAM-02"}
    correlations = correlate_cross_camera_events(events, time_window_seconds=30.0, camera_map=camera_map)

    # Since neither cluster spans >= 2 cameras, no cross-camera correlation should be declared
    assert len(correlations) == 0


def test_correlate_cross_camera_events_single_camera_ignored():
    t_base = datetime(2026, 3, 1, 10, 30, 0, tzinfo=timezone.utc)

    # Only Camera 1 detects person repeatedly
    events = [
        TimelineEvent(
            id="ev-1",
            evidence_id="EVD-01",
            description="AI Detection: person (0.85)",
            normalized_timestamp_utc=t_base,
        ),
        TimelineEvent(
            id="ev-2",
            evidence_id="EVD-01",
            description="AI Detection: person (0.88)",
            normalized_timestamp_utc=t_base + timedelta(seconds=5),
        ),
    ]

    camera_map = {"EVD-01": "CAM-01"}
    correlations = correlate_cross_camera_events(events, time_window_seconds=30.0, camera_map=camera_map)

    assert len(correlations) == 0


def test_correlate_cross_camera_events_different_entities_not_merged():
    t_base = datetime(2026, 3, 1, 10, 30, 0, tzinfo=timezone.utc)

    # Camera 1 detects person at T=0
    # Camera 2 detects vehicle at T=5s
    events = [
        TimelineEvent(
            id="ev-1",
            evidence_id="EVD-01",
            description="AI Detection: person (0.85)",
            normalized_timestamp_utc=t_base,
        ),
        TimelineEvent(
            id="ev-2",
            evidence_id="EVD-02",
            description="AI Detection: vehicle (0.91)",
            normalized_timestamp_utc=t_base + timedelta(seconds=5),
        ),
    ]

    camera_map = {"EVD-01": "CAM-01", "EVD-02": "CAM-02"}
    correlations = correlate_cross_camera_events(events, time_window_seconds=30.0, camera_map=camera_map)

    assert len(correlations) == 0


def test_get_case_cross_camera_correlations_database_integration():
    with session_scope() as session:
        case = create_case(session, "CASE-CORR-01", "Cross Camera Correlation Case", "Investigator Holmes")

        # Two evidence items representing two cameras
        ev1 = EvidenceItem(
            case_id=case.id,
            evidence_number="EX-CAM-01",
            source_filename="cam01_gate.mp4",
            sanitized_filename="cam01_gate.mp4",
            file_size_bytes=1000,
            imported_by="Holmes",
            imported_at_utc=now_utc(),
        )
        ev2 = EvidenceItem(
            case_id=case.id,
            evidence_number="EX-CAM-02",
            source_filename="cam02_driveway.mp4",
            sanitized_filename="cam02_driveway.mp4",
            file_size_bytes=1000,
            imported_by="Holmes",
            imported_at_utc=now_utc(),
        )
        session.add_all([ev1, ev2])
        session.flush()

        t_base = datetime(2026, 3, 1, 14, 0, 0, tzinfo=timezone.utc)

        # Event on Cam 1: Vehicle at 14:00:00
        create_timeline_event(
            session,
            case_id=case.id,
            event_type=TimelineEventType.AI_PRELIMINARY.value,
            evidence_id=ev1.id,
            raw_timestamp="2026-03-01T14:00:00Z",
            normalized_utc=t_base,
            description="AI Detection: vehicle (0.92)",
        )

        # Event on Cam 2: Vehicle at 14:00:18 (within 30s)
        create_timeline_event(
            session,
            case_id=case.id,
            event_type=TimelineEventType.AI_PRELIMINARY.value,
            evidence_id=ev2.id,
            raw_timestamp="2026-03-01T14:00:18Z",
            normalized_utc=t_base + timedelta(seconds=18),
            description="AI Detection: car (0.87)",
        )

        corrs = get_case_cross_camera_correlations(session, case.id, time_window_seconds=30.0)
        assert len(corrs) == 1
        c = corrs[0]
        assert c["entity_type"] == "vehicle"
        assert c["camera_count"] == 2
        assert "EX-CAM-01" in c["cameras"]
        assert "EX-CAM-02" in c["cameras"]
        assert c["time_span_seconds"] == 18.0
        assert len(c["events"]) == 2

