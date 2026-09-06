"""
tests/test_ai.py
----------------
Unit and integration tests for AI-assisted video forensic triage,
pretrained YOLOv8n object detection, offline ML heuristic engine,
custody event logging, and analyst review workflows.

Phase 6: Updated for Pretrained YOLOv8n and Analyst Review Split.
"""

import tempfile
from pathlib import Path
import cv2
import numpy as np
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
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_MODEL_NAME,
    RELEVANT_CLASSES,
    get_ai_status,
    get_ai_status_info,
    is_gemini_available,
    is_yolo_available,
    list_detections_for_case,
    list_detections_for_evidence,
    list_detections_for_segment,
    review_detection,
    run_ai_triage,
)
from forensiq.services.case_service import create_case
from forensiq.services.report_service import _collect_report_data
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


@pytest.fixture
def synthetic_video_path():
    """Create a temporary valid MP4 video with blank frames for video capture tests."""
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tf:
        temp_video = Path(tf.name)

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    out = cv2.VideoWriter(str(temp_video), fourcc, 10.0, (64, 64))
    for _ in range(25):
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        out.write(frame)
    out.release()

    yield temp_video

    if temp_video.exists():
        temp_video.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Required Prompt Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_ai_detection_pending_by_default(segment_fixture):
    """Requirement: AI detection is created with reviewer_status PENDING by default."""
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        detections = run_ai_triage(
            session=session,
            segment_id=segment_id,
            actor_id="Analyst John",
            confidence_threshold=0.45,
        )

        assert len(detections) >= 1
        for det in detections:
            # Forensic guarantee: Must be PENDING by default, never CONFIRMED
            assert det.reviewer_status == ReviewerStatus.PENDING.value
            assert det.reviewed_at_utc is None
            assert det.reviewer_id is None

            # Verify associated timeline event is also PENDING
            events = (
                session.query(TimelineEvent)
                .filter_by(segment_id=segment_id, event_type=TimelineEventType.AI_PRELIMINARY.value)
                .all()
            )
            for ev in events:
                assert ev.analyst_status == AnalystStatus.PENDING.value
                assert "AI Detection:" in ev.description


def test_confirm_and_reject_findings_split(segment_fixture):
    """
    Requirement: Confirming a detection updates its status and it appears under
    confirmed findings; rejecting removes it from confirmed findings.
    """
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        detections = run_ai_triage(session=session, segment_id=segment_id, actor_id="Analyst John")
        det = detections[0]
        det_id = det.id

        # 1. Initially all are in preliminary annotations
        report_data = _collect_report_data(session, case_id)
        assert any(d.id == det_id for d in report_data["ai_preliminary_annotations"])
        assert not any(d.id == det_id for d in report_data["ai_confirmed_findings"])

        # 2. Confirm the detection
        reviewed = review_detection(
            session=session,
            detection_id=det_id,
            reviewer_status=ReviewerStatus.CONFIRMED.value,
            reviewer_id="Lead Investigator",
            notes="Confirmed suspect vehicle match",
        )
        assert reviewed.reviewer_status == ReviewerStatus.CONFIRMED.value
        assert reviewed.reviewer_id == "Lead Investigator"

        # Now appears under confirmed findings, NOT preliminary
        report_data_confirmed = _collect_report_data(session, case_id)
        assert any(d.id == det_id for d in report_data_confirmed["ai_confirmed_findings"])
        assert not any(d.id == det_id for d in report_data_confirmed["ai_preliminary_annotations"])

        # 3. Reject the detection
        rejected = review_detection(
            session=session,
            detection_id=det_id,
            reviewer_status=ReviewerStatus.REJECTED.value,
            reviewer_id="Lead Investigator",
            notes="False alarm: tree reflection",
        )
        assert rejected.reviewer_status == ReviewerStatus.REJECTED.value

        # Removed from confirmed findings, now appears under preliminary/rejected
        report_data_rejected = _collect_report_data(session, case_id)
        assert not any(d.id == det_id for d in report_data_rejected["ai_confirmed_findings"])
        assert any(d.id == det_id for d in report_data_rejected["ai_preliminary_annotations"])


def test_yolo_triage_relevant_classes_filter(segment_fixture, synthetic_video_path, monkeypatch):
    """
    Requirement: Running AI triage on a mocked frame produces detections only for
    classes in the relevant-classes filter (person, car, motorcycle, bus, truck).
    Mock the YOLO call without requiring real model file to be present in CI.
    """
    case_id, evidence_id, segment_id = segment_fixture

    class MockTensor:
        def __init__(self, val):
            self.val = val
        def __getitem__(self, idx):
            return self.val[idx] if isinstance(self.val, list) else self.val
        def tolist(self):
            return self.val

    class MockBox:
        def __init__(self, cls_id: int, conf: float, xyxy: list[float]):
            self.cls = MockTensor(cls_id)
            self.conf = MockTensor(conf)
            self.xyxy = MockTensor([xyxy])

    class MockResult:
        def __init__(self, boxes):
            self.boxes = boxes

    class MockYOLOModel:
        names = {
            0: "person",
            2: "car",
            3: "motorcycle",
            5: "bus",
            7: "truck",
            16: "dog",
            56: "chair",
            67: "cell phone",
        }

        def predict(self, frame, conf=0.45, classes=None, verbose=False):
            # Return mix of allowed and non-allowed COCO classes
            all_boxes = [
                MockBox(0, 0.88, [0.1, 0.1, 0.3, 0.6]),     # person (allowed)
                MockBox(2, 0.79, [0.4, 0.4, 0.8, 0.8]),     # car (allowed)
                MockBox(16, 0.95, [0.2, 0.2, 0.4, 0.4]),    # dog (disallowed)
                MockBox(56, 0.82, [0.5, 0.5, 0.7, 0.7]),    # chair (disallowed)
            ]
            # When classes parameter is passed, YOLO filters by allowed classes:
            filtered_boxes = [b for b in all_boxes if (classes is None or int(b.cls[0]) in classes)]
            return [MockResult(filtered_boxes)]

    mock_model = MockYOLOModel()
    monkeypatch.setattr("forensiq.services.ai_service.is_yolo_available", lambda: True)
    monkeypatch.setattr("forensiq.services.ai_service._get_yolo_model", lambda: mock_model)
    monkeypatch.setattr("forensiq.services.adapter_service.get_working_copy_path", lambda s, eid: synthetic_video_path)

    with session_scope() as session:
        detections = run_ai_triage(session=session, segment_id=segment_id, actor_id="Investigator Mock")

        assert len(detections) >= 1
        allowed_names = {"person", "car", "motorcycle", "bus", "truck"}
        for d in detections:
            assert d.class_name in allowed_names
            assert d.class_name not in {"dog", "chair", "cell phone"}
            assert d.model_name == DEFAULT_MODEL_NAME
            assert d.reviewer_status == ReviewerStatus.PENDING.value


def test_ai_model_load_failure_returns_unavailable(monkeypatch, tmp_path):
    """
    Requirement: If the model fails to load, the service returns an 'unavailable'
    status rather than raising an unhandled exception.
    """
    # 1. Point to a non-existent weights path
    non_existent = tmp_path / "missing_yolo.pt"
    monkeypatch.setattr("forensiq.config.YOLO_MODEL_PATH", str(non_existent))
    monkeypatch.setattr("forensiq.services.ai_service._yolo_instance", None)

    status = get_ai_status()
    assert status == "unavailable"

    info = get_ai_status_info()
    assert info["status"] == "unavailable"
    assert info["available"] is False
    assert "not found" in info["reason"].lower() or "not loaded" in info["reason"].lower()

    # 2. Corrupt or unreadable model path: verify no unhandled exception
    corrupt_file = tmp_path / "corrupt_weights.pt"
    corrupt_file.write_text("corrupted content", encoding="utf-8")
    monkeypatch.setattr("forensiq.config.YOLO_MODEL_PATH", str(corrupt_file))
    monkeypatch.setattr("forensiq.services.ai_service._yolo_instance", None)

    status_corrupt = get_ai_status()
    assert status_corrupt == "unavailable"

    info_corrupt = get_ai_status_info()
    assert info_corrupt["status"] == "unavailable"
    assert info_corrupt["available"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Additional Unit & Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_is_gemini_available(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-12345")
    assert is_gemini_available() is True

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert is_gemini_available() is False


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


def test_list_detections_for_evidence_and_case(segment_fixture):
    case_id, evidence_id, segment_id = segment_fixture

    with session_scope() as session:
        run_ai_triage(session=session, segment_id=segment_id)

        by_ev = list_detections_for_evidence(session, evidence_id)
        assert len(by_ev) >= 1

        by_seg = list_detections_for_segment(session, segment_id)
        assert len(by_seg) >= 1

        by_case = list_detections_for_case(session, case_id)
        assert len(by_case) >= 1
