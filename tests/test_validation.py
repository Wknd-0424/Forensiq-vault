"""
tests/test_validation.py
------------------------
Unit and integration tests for the forensic validation engine.

Phase 4: Fully implemented.
"""

from datetime import datetime, timezone

import pytest

from forensiq.constants import CustodyAction
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.evidence import EvidenceItem
from forensiq.models.validation import ValidationRun
from forensiq.services.case_service import create_case
from forensiq.services.validation_service import (
    ValidationStatus,
    check_container_codec,
    check_duration_and_bitrate,
    check_timestamps,
    check_video_dimensions,
    get_latest_validation_run,
    run_validation,
)
from forensiq.utils.utc_utils import now_utc


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to isolated SQLite."""
    db_url = f"sqlite:///{tmp_path / 'test_validation.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


# ─────────────────────────────────────────────────────────────────────────────
# Unit Tests for Individual Checks
# ─────────────────────────────────────────────────────────────────────────────

def test_check_container_codec_valid():
    parsed = {
        "container": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
        "video_streams": [{"index": 0, "codec_name": "h264"}],
    }
    res = check_container_codec(parsed)
    assert res["status"] == ValidationStatus.PASSED
    assert "consistent" in res["message"]


def test_check_container_codec_unusual():
    parsed = {
        "container": {"format_name": "mp4"},
        "video_streams": [{"index": 0, "codec_name": "unknown_raw_codec"}],
    }
    res = check_container_codec(parsed)
    assert res["status"] == ValidationStatus.WARNING
    assert "unusual" in res["message"]


def test_check_timestamps_plausible():
    parsed = {
        "container": {"creation_time": "2024-05-15T12:00:00.000000Z"}
    }
    res = check_timestamps(parsed)
    assert res["status"] == ValidationStatus.PASSED
    assert "plausible" in res["message"]


def test_check_timestamps_future():
    # Year 2099 is definitely in the future
    parsed = {
        "container": {"creation_time": "2099-01-01T00:00:00.000000Z"}
    }
    res = check_timestamps(parsed)
    assert res["status"] == ValidationStatus.FAILED
    assert "TIMESTAMP ANOMALY" in res["message"]


def test_check_timestamps_pre_1990():
    # Year 1980 indicates battery failure / unconfigured clock
    parsed = {
        "container": {"creation_time": "1980-01-01 00:00:00"}
    }
    res = check_timestamps(parsed)
    assert res["status"] == ValidationStatus.WARNING
    assert "SUSPICIOUS DATE" in res["message"]
    assert "RTC battery failure" in res["message"]


def test_check_timestamps_missing():
    parsed = {"container": {"creation_time": None}}
    res = check_timestamps(parsed)
    assert res["status"] == ValidationStatus.WARNING
    assert "No creation_time" in res["message"]


def test_check_duration_and_bitrate_consistent():
    # 10 seconds at 800,000 bps = 1,000,000 bytes
    parsed = {
        "container": {"duration_sec": 10.0, "bit_rate": 800000}
    }
    res = check_duration_and_bitrate(parsed, file_size_bytes=980000)
    assert res["status"] == ValidationStatus.PASSED


def test_check_duration_and_bitrate_truncated():
    # 100 seconds at 8,000,000 bps = 100,000,000 bytes
    # But actual file size is only 1,000,000 bytes (ratio = 0.01 < 0.4)
    parsed = {
        "container": {"duration_sec": 100.0, "bit_rate": 8000000}
    }
    res = check_duration_and_bitrate(parsed, file_size_bytes=1000000)
    assert res["status"] == ValidationStatus.FAILED
    assert "POSSIBLE TRUNCATION" in res["message"]


def test_check_video_dimensions_valid():
    parsed = {
        "video_streams": [{"index": 0, "width": 1920, "height": 1080, "fps": 25.0}]
    }
    res = check_video_dimensions(parsed)
    assert res["status"] == ValidationStatus.PASSED
    assert "1920x1080" in res["message"]


def test_check_video_dimensions_invalid():
    parsed = {
        "video_streams": [{"index": 0, "width": 0, "height": 0, "fps": 25.0}]
    }
    res = check_video_dimensions(parsed)
    assert res["status"] == ValidationStatus.FAILED
    assert "Invalid video dimensions" in res["message"]


def test_check_video_dimensions_missing_fps():
    parsed = {
        "video_streams": [{"index": 0, "width": 1920, "height": 1080, "fps": None}]
    }
    res = check_video_dimensions(parsed)
    assert res["status"] == ValidationStatus.WARNING
    assert "Frame rate is missing" in res["message"]


# ─────────────────────────────────────────────────────────────────────────────
# Integration: run_validation
# ─────────────────────────────────────────────────────────────────────────────

def test_run_validation_passed():
    with session_scope() as session:
        case = create_case(session, "CASE-VAL-001", "Case", investigator_name="Officer")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-VAL-001",
            source_filename="good_clip.mp4",
            sanitized_filename="good_clip.mp4",
            file_size_bytes=1000000,
            imported_by="Officer",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        parsed = {
            "container": {
                "format_name": "mp4",
                "creation_time": "2024-06-01T12:00:00Z",
                "duration_sec": 10.0,
                "bit_rate": 800000,
            },
            "video_streams": [
                {"index": 0, "codec_name": "h264", "width": 1920, "height": 1080, "fps": 30.0}
            ],
            "audio_streams": [],
        }

        run_rec, results = run_validation(
            session=session,
            evidence_id=item.id,
            parsed_metadata=parsed,
            actor_id="Analyst Mark",
        )

        assert run_rec.status == ValidationStatus.PASSED
        assert len(results) == 4
        assert run_rec.performed_by == "Analyst Mark"

        # Verify custody event
        ev = (
            session.query(CustodyEvent)
            .filter_by(evidence_id=item.id, action=CustodyAction.VALIDATION_RUN.value)
            .first()
        )
        assert ev is not None
        assert ev.actor_id == "Analyst Mark"

        # Verify get_latest_validation_run
        latest = get_latest_validation_run(session, item.id)
        assert latest is not None
        assert latest.id == run_rec.id


def test_run_validation_failed_rollup():
    with session_scope() as session:
        case = create_case(session, "CASE-VAL-002", "Case", investigator_name="Officer")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-VAL-002",
            source_filename="anomalous.mp4",
            sanitized_filename="anomalous.mp4",
            file_size_bytes=10000,
            imported_by="Officer",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        # Parsed with future timestamp -> will fail
        parsed = {
            "container": {
                "format_name": "mp4",
                "creation_time": "2099-01-01T00:00:00Z",
                "duration_sec": 10.0,
                "bit_rate": 800000,
            },
            "video_streams": [
                {"index": 0, "codec_name": "h264", "width": 1920, "height": 1080, "fps": 30.0}
            ],
            "audio_streams": [],
        }

        run_rec, results = run_validation(
            session=session,
            evidence_id=item.id,
            parsed_metadata=parsed,
            actor_id="Analyst Mark",
        )

        assert run_rec.status == ValidationStatus.FAILED
