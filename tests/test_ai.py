"""
tests/test_ai.py
----------------
Unit and integration tests for AI-assisted video forensic triage,
local heuristic detection engine, custody event logging, and analyst review workflows.

Phase 5: Fully implemented.
"""

import pytest

from forensiq.constants import (
    AnalystStatus,
    CustodyAction,
    ReviewerStatus,
    TimelineEventType,
)
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.detection import AIDetection
from forensiq.models.evidence import EvidenceItem
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.services.ai_service import (
    is_gemini_available,
    is_yolo_available,
    list_detections_for_case,
    list_detections_for_segment,
    review_detection,
    run_ai_triage,
)
from forensiq.services.case_service import create_case
from forensiq.services.timeline_service import create_or_update_segment_from_evidence
from forensiq.utils.utc_utils import now_utc


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to isolated SQLite."""
    db_url = f"sqlite:///{tmp_path / 'test_ai.db'}"
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
def segment_fixture():
    with session_scope() as session:
        case = create_case(session, "CASE-AI-001", "AI Case", investigator_name="Analyst John")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-AI-01",
            source_filename="perimeter_cam.mp4",
            sanitized_filename="perimeter_cam.mp4",
            file_size_bytes=52428800,
            imported_by="Analyst John",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        segment = VideoSegment(
            evidence_id=item.id,
            channel_id="CH-01",
            duration_seconds=35.0,
            raw_start_time="2026-03-01T12:00:00Z",
            normalized_start_utc=now_utc(),
            codec="h264",
            resolution="1920x1080",
            frame_rate="30.0",
            parse_status="PARSED",
        )
        session.add(segment)
        session.flush()

        case_id = case.id
        evidence_id = item.id
        segment_id = segment.id

    return case_id, evidence_id, segment_id


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_is_gemini_available(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-12345")
    assert is_gemini_available() is True

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert is_gemini_available() is False


def test_run_ai_triage_local_heuristic(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        detections = run_ai_triage(
            session=session,
            segment_id=segment_id,
            actor_id="Analyst John",
            confidence_threshold=0.6,
        )

        assert len(detections) >= 2

        # Verify classes are in allowed set
        allowed_classes = {"motion", "vehicle", "person", "scene_change"}
        for d in detections:
            assert d.class_name in allowed_classes
            assert d.confidence >= 0.6
            # Strict forensic constraint: initial status must be PENDING
            assert d.reviewer_status == ReviewerStatus.PENDING.value
            assert d.segment_id == segment_id

        # Verify STRICT PROHIBITION: No face recognition
        class_names = [d.class_name.lower() for d in detections]
        assert "face" not in class_names
        assert "face_recognition" not in class_names
        assert "identity" not in class_names

        # Verify corresponding TimelineEvents created
        events = (
            session.query(TimelineEvent)
            .filter_by(segment_id=segment_id, event_type=TimelineEventType.AI_PRELIMINARY.value)
            .all()
        )
        assert len(events) == len(detections)
        for ev in events:
            assert ev.analyst_status == AnalystStatus.PENDING.value
            assert "AI Detection" in ev.description


def test_run_ai_triage_custody_events(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        run_ai_triage(session=session, segment_id=segment_id, actor_id="Analyst John")

        # Verify AI_ANALYSIS_STARTED
        start_ev = (
            session.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id, action=CustodyAction.AI_ANALYSIS_STARTED.value)
            .first()
        )
        assert start_ev is not None
        assert start_ev.actor_id == "Analyst John"

        # Verify AI_ANALYSIS_COMPLETED
        comp_ev = (
            session.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id, action=CustodyAction.AI_ANALYSIS_COMPLETED.value)
            .first()
        )
        assert comp_ev is not None
        assert comp_ev.actor_id == "Analyst John"
        assert comp_ev.event_hash is not None


def test_review_detection_confirmed(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        detections = run_ai_triage(session=session, segment_id=segment_id, actor_id="Analyst John")
        det = detections[0]

        reviewed = review_detection(
            session=session,
            detection_id=det.id,
            reviewer_status=ReviewerStatus.CONFIRMED.value,
            reviewer_id="Senior Investigator",
            notes="Confirmed suspect vehicle entering compound",
        )

        assert reviewed.reviewer_status == ReviewerStatus.CONFIRMED.value
        assert reviewed.reviewer_id == "Senior Investigator"
        assert reviewed.reviewed_at_utc is not None

        # Verify linked custody event
        rev_ev = (
            session.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id, action=CustodyAction.DETECTION_REVIEWED.value)
            .first()
        )
        assert rev_ev is not None
        assert rev_ev.actor_id == "Senior Investigator"
        assert "CONFIRMED" in rev_ev.reason


def test_review_detection_rejected(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        detections = run_ai_triage(session=session, segment_id=segment_id, actor_id="Analyst John")
        det = detections[0]

        reviewed = review_detection(
            session=session,
            detection_id=det.id,
            reviewer_status=ReviewerStatus.REJECTED.value,
            reviewer_id="Senior Investigator",
            notes="Tree branches waving in the wind",
        )

        assert reviewed.reviewer_status == ReviewerStatus.REJECTED.value
        assert reviewed.reviewer_id == "Senior Investigator"


def test_list_detections(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        run_ai_triage(session=session, segment_id=segment_id)

        by_seg = list_detections_for_segment(session, segment_id)
        assert len(by_seg) >= 2

        by_case = list_detections_for_case(session, case_id)
        assert len(by_case) >= 2


def test_is_yolo_available(monkeypatch, tmp_path):
    assert is_yolo_available() in (True, False)
    # When YOLO_MODEL_PATH does not exist:
    non_existent = tmp_path / "non_existent.pt"
    monkeypatch.setattr("forensiq.config.YOLO_MODEL_PATH", non_existent)
    assert is_yolo_available() is False


def test_yolo_triage_with_synthetic_working_copy(segment_fixture, monkeypatch):
    case_id, evidence_id, segment_id = segment_fixture

    class DummyBox:
        def __init__(self):
            import torch
            self.cls = torch.tensor([0])  # person
            self.conf = torch.tensor([0.89])
            self.xyxyn = torch.tensor([[0.2, 0.3, 0.4, 0.7]])

    class DummyResult:
        def __init__(self):
            self.boxes = [DummyBox()]

    class DummyModel:
        names = {0: "person", 2: "car"}
        def predict(self, frame, conf=0.5, verbose=False):
            return [DummyResult()]

    monkeypatch.setattr("forensiq.services.ai_service.is_yolo_available", lambda: True)
    monkeypatch.setattr("forensiq.services.ai_service._get_yolo_model", lambda: DummyModel())

    import numpy as np
    import cv2
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tf:
        temp_video = Path(tf.name)

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    out = cv2.VideoWriter(str(temp_video), fourcc, 10.0, (64, 64))
    for _ in range(25):
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        out.write(frame)
    out.release()

    try:
        monkeypatch.setattr("forensiq.services.adapter_service.get_working_copy_path", lambda session, eid: temp_video)

        with session_scope() as session:
            dets = run_ai_triage(session=session, segment_id=segment_id, actor_id="Investigator YOLO")
            assert len(dets) >= 1
            assert any(d.class_name == "person" for d in dets)
            assert any("YOLO" in d.model_name for d in dets)
    finally:
        if temp_video.exists():
            temp_video.unlink(missing_ok=True)
