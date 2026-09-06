"""
tests/test_metadata.py
-----------------------
Unit and integration tests for ffprobe metadata extraction and persistence.

Phase 4: Fully implemented.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forensiq.constants import CustodyAction
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.services.case_service import create_case
from forensiq.services.metadata_service import (
    MetadataExtractionError,
    _format_duration,
    _parse_frame_rate,
    get_metadata_for_evidence,
    is_ffprobe_available,
    parse_metadata,
    persist_metadata,
    run_ffprobe,
)
from forensiq.utils.utc_utils import now_utc

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic ffprobe output fixture
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_FFPROBE_DICT = {
    "format": {
        "filename": "surveillance_cam01.mp4",
        "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
        "format_long_name": "QuickTime / MOV",
        "start_time": "0.000000",
        "duration": "124.500000",
        "size": "32450000",
        "bit_rate": "2085140",
        "tags": {
            "major_brand": "isom",
            "minor_version": "512",
            "compatible_brands": "isomiso2avc1mp41",
            "creation_time": "2026-03-01T10:15:30.000000Z",
        },
    },
    "streams": [
        {
            "index": 0,
            "codec_name": "h264",
            "codec_long_name": "H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10",
            "profile": "High",
            "codec_type": "video",
            "width": 1920,
            "height": 1080,
            "display_aspect_ratio": "16:9",
            "pix_fmt": "yuv420p",
            "r_frame_rate": "25/1",
            "avg_frame_rate": "25/1",
            "nb_frames": "3112",
            "bit_rate": "1950000",
            "color_space": "bt709",
            "tags": {"language": "und"},
        },
        {
            "index": 1,
            "codec_name": "aac",
            "codec_long_name": "AAC (Advanced Audio Coding)",
            "codec_type": "audio",
            "channels": 2,
            "channel_layout": "stereo",
            "sample_rate": "48000",
            "bit_rate": "128000",
            "tags": {"language": "und"},
        },
    ],
}


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to isolated SQLite."""
    db_url = f"sqlite:///{tmp_path / 'test_meta.db'}"
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
def test_evidence(tmp_path):
    """Create a case and an evidence item in the test DB."""
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="CASE-META-001",
            title="Metadata Test Case",
            investigator_name="Inspector Smith",
        )
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-001",
            source_filename="test_cam.mp4",
            sanitized_filename="test_cam.mp4",
            file_size_bytes=32450000,
            original_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            original_md5="d41d8cd98f00b204e9800998ecf8427e",
            imported_by="Inspector Smith",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()
        case_id = case.id
        evidence_id = item.id
    return case_id, evidence_id


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_frame_rate():
    assert _parse_frame_rate("25/1") == 25.0
    assert _parse_frame_rate("30000/1001") == 29.97
    assert _parse_frame_rate("29.97") == 29.97
    assert _parse_frame_rate("0/0") is None
    assert _parse_frame_rate("") is None
    assert _parse_frame_rate(None) is None
    assert _parse_frame_rate("invalid/str") is None


def test_format_duration():
    assert _format_duration(84.3) == "00:01:24.300"
    assert _format_duration(3661.0) == "01:01:01.000"
    assert _format_duration(0.0) == "00:00:00.000"
    assert _format_duration(None) is None


def test_is_ffprobe_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/ffprobe" if cmd == "ffprobe" else None)
    monkeypatch.setattr("forensiq.config.FFPROBE_PATH", "ffprobe")
    assert is_ffprobe_available() is True

    monkeypatch.setattr("shutil.which", lambda cmd: None)
    monkeypatch.setattr("pathlib.Path.is_file", lambda self: False)
    assert is_ffprobe_available() is False


def test_run_ffprobe_missing_tool(monkeypatch, tmp_path):
    monkeypatch.setattr("forensiq.services.metadata_service.is_ffprobe_available", lambda: False)
    fake_file = tmp_path / "fake.mp4"
    fake_file.write_text("fake")
    with pytest.raises(MetadataExtractionError, match="ffprobe executable not found"):
        run_ffprobe(fake_file)


def test_run_ffprobe_success(monkeypatch, tmp_path):
    fake_file = tmp_path / "fake.mp4"
    fake_file.write_text("fake")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(SAMPLE_FFPROBE_DICT)
    mock_proc.stderr = ""

    monkeypatch.setattr("forensiq.services.metadata_service.is_ffprobe_available", lambda: True)
    with patch("subprocess.run", return_value=mock_proc):
        res = run_ffprobe(fake_file)
        assert "format" in res
        assert res["format"]["format_name"] == "mov,mp4,m4a,3gp,3g2,mj2"


def test_run_ffprobe_timeout(monkeypatch, tmp_path):
    fake_file = tmp_path / "fake.mp4"
    fake_file.write_text("fake")

    monkeypatch.setattr("forensiq.services.metadata_service.is_ffprobe_available", lambda: True)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ffprobe", timeout=5)):
        with pytest.raises(MetadataExtractionError, match="timed out"):
            run_ffprobe(fake_file, timeout=5)


def test_run_ffprobe_invalid_json(monkeypatch, tmp_path):
    fake_file = tmp_path / "fake.mp4"
    fake_file.write_text("fake")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "This is not JSON text at all"
    mock_proc.stderr = ""

    monkeypatch.setattr("forensiq.services.metadata_service.is_ffprobe_available", lambda: True)
    with patch("subprocess.run", return_value=mock_proc):
        with pytest.raises(MetadataExtractionError, match="invalid JSON"):
            run_ffprobe(fake_file)


def test_parse_metadata_structure():
    parsed = parse_metadata(SAMPLE_FFPROBE_DICT)

    # Container
    container = parsed["container"]
    assert container["format_name"] == "mov,mp4,m4a,3gp,3g2,mj2"
    assert container["duration_sec"] == 124.5
    assert container["duration_formatted"] == "00:02:04.500"
    assert container["size_bytes"] == 32450000
    assert container["bit_rate"] == 2085140
    assert container["creation_time"] == "2026-03-01T10:15:30.000000Z"

    # Video stream
    assert len(parsed["video_streams"]) == 1
    v = parsed["video_streams"][0]
    assert v["codec_name"] == "h264"
    assert v["width"] == 1920
    assert v["height"] == 1080
    assert v["resolution"] == "1920x1080"
    assert v["fps"] == 25.0
    assert v["pix_fmt"] == "yuv420p"
    assert v["nb_frames"] == 3112

    # Audio stream
    assert len(parsed["audio_streams"]) == 1
    a = parsed["audio_streams"][0]
    assert a["codec_name"] == "aac"
    assert a["channels"] == 2
    assert a["sample_rate"] == 48000


def test_persist_metadata(test_evidence):
    case_id, evidence_id = test_evidence
    parsed = parse_metadata(SAMPLE_FFPROBE_DICT)

    with session_scope() as session:
        records = persist_metadata(
            session=session,
            evidence_id=evidence_id,
            case_id=case_id,
            parsed_metadata=parsed,
            actor_id="Investigator Jane",
        )

        assert len(records) > 10

        # Verify format records
        fmt_name = session.query(MetadataRecord).filter_by(
            evidence_id=evidence_id, namespace="format", key="format_name"
        ).first()
        assert fmt_name is not None
        assert fmt_name.raw_value == "mov,mp4,m4a,3gp,3g2,mj2"

        # Verify video record
        v_res = session.query(MetadataRecord).filter_by(
            evidence_id=evidence_id, namespace="video:0", key="resolution"
        ).first()
        assert v_res is not None
        assert v_res.raw_value == "1920x1080"

        # Verify audio record
        a_sr = session.query(MetadataRecord).filter_by(
            evidence_id=evidence_id, namespace="audio:1", key="sample_rate"
        ).first()
        assert a_sr is not None
        assert a_sr.normalized_value == "48000 Hz"

        # Verify custody event
        ev = (
            session.query(CustodyEvent)
            .filter_by(evidence_id=evidence_id, action=CustodyAction.METADATA_EXTRACTED.value)
            .first()
        )
        assert ev is not None
        assert ev.actor_id == "Investigator Jane"
        assert ev.event_hash is not None


def test_persist_metadata_idempotence(test_evidence):
    case_id, evidence_id = test_evidence
    parsed = parse_metadata(SAMPLE_FFPROBE_DICT)

    with session_scope() as session:
        # First persistence
        persist_metadata(
            session=session,
            evidence_id=evidence_id,
            case_id=case_id,
            parsed_metadata=parsed,
            actor_id="Investigator Jane",
        )
        count_first = session.query(MetadataRecord).filter_by(evidence_id=evidence_id).count()

        # Second persistence with same data
        persist_metadata(
            session=session,
            evidence_id=evidence_id,
            case_id=case_id,
            parsed_metadata=parsed,
            actor_id="Investigator Jane",
        )
        count_second = session.query(MetadataRecord).filter_by(evidence_id=evidence_id).count()

        # Prior records were cleared, so count must match exactly
        assert count_first == count_second


def test_get_metadata_for_evidence(test_evidence):
    case_id, evidence_id = test_evidence
    parsed = parse_metadata(SAMPLE_FFPROBE_DICT)

    with session_scope() as session:
        persist_metadata(
            session=session,
            evidence_id=evidence_id,
            case_id=case_id,
            parsed_metadata=parsed,
        )

        records = get_metadata_for_evidence(session, evidence_id)
        assert len(records) > 0
        # Check ordering: namespace, then key
        for i in range(len(records) - 1):
            curr_tuple = (records[i].namespace, records[i].key)
            next_tuple = (records[i + 1].namespace, records[i + 1].key)
            assert curr_tuple <= next_tuple


# ─────────────────────────────────────────────────────────────────────────────
# UI Tests for VideoMetadataPage
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_video_metadata_page_no_active_case(qapp):
    from forensiq.ui.pages.video_metadata_page import VideoMetadataPage

    class MockMainWindow:
        active_case_id = None
        active_evidence_id = None
        def set_active_evidence_id(self, ev_id): pass

    mock_mw = MockMainWindow()
    page = VideoMetadataPage(main_window=mock_mw)
    page.refresh()

    assert not page._evidence_combo.isEnabled()
    assert not page._analyze_btn.isEnabled()
    assert not page._validate_btn.isEnabled()
    assert page._tabs.count() == 3


def test_video_metadata_page_with_evidence(qapp, test_evidence):
    case_id, evidence_id = test_evidence
    from forensiq.ui.pages.video_metadata_page import VideoMetadataPage

    class MockMainWindow:
        active_case_id = case_id
        active_evidence_id = evidence_id
        def set_active_evidence_id(self, ev_id): pass

    mock_mw = MockMainWindow()
    page = VideoMetadataPage(main_window=mock_mw)
    page.refresh()

    assert page._evidence_combo.isEnabled()
    assert page._evidence_combo.count() == 1
    assert page._analyze_btn.isEnabled()


def test_video_metadata_page_with_stored_metadata(qapp, test_evidence):
    case_id, evidence_id = test_evidence
    from forensiq.models.validation import ValidationRun
    from forensiq.services.validation_service import ValidationStatus
    from forensiq.ui.pages.video_metadata_page import VideoMetadataPage

    parsed = parse_metadata(SAMPLE_FFPROBE_DICT)
    with session_scope() as session:
        persist_metadata(session, evidence_id, case_id, parsed)
        val_run = ValidationRun(
            evidence_id=evidence_id,
            validation_type="FORENSIC_SANITY_SUITE",
            status=ValidationStatus.PASSED,
            results_json=json.dumps([{"check": "Test", "status": "PASSED", "message": "OK"}]),
            performed_by="Analyst",
            performed_at_utc=now_utc(),
            tool_version="1.0.0",
        )
        session.add(val_run)

    class MockMainWindow:
        active_case_id = case_id
        active_evidence_id = evidence_id
        def set_active_evidence_id(self, ev_id): pass

    mock_mw = MockMainWindow()
    page = VideoMetadataPage(main_window=mock_mw)
    page.refresh()

    # Cards populated
    assert page._c_fmt.text() == "mov,mp4,m4a,3gp,3g2,mj2"
    assert page._v_codec.text() == "h264"
    assert page._v_res.text() == "1920x1080"
    assert page._val_status.text() == "PASSED"
    assert page._validate_btn.isEnabled()
