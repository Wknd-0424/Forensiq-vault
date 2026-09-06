"""
tests/test_adapters.py
----------------------
Unit and integration tests for vendor adapters and the adapter registry.

Phase 4: Fully implemented.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forensiq.adapters.base import AdapterResponse, BaseAdapter
from forensiq.adapters.generic_media import GenericMediaAdapter
from forensiq.adapters.registry import AdapterRegistry, get_registry
from forensiq.adapters.unknown_source import UnknownSourceAdapter
from forensiq.constants import CustodyAction, EvidenceStatus
from forensiq.database import init_db, session_scope
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.metadata import MetadataRecord
from forensiq.services.adapter_service import (
    analyze_evidence,
    detect_adapter_for_evidence,
    get_working_copy_path,
)
from forensiq.services.case_service import create_case
from forensiq.utils.utc_utils import now_utc

SAMPLE_PARSED = {
    "container": {
        "format_name": "mov,mp4",
        "duration_sec": 42.0,
        "duration_formatted": "00:00:42.000",
        "size_bytes": 1048576,
        "bit_rate": 200000,
        "creation_time": "2026-03-01T10:00:00Z",
        "tags": {},
    },
    "video_streams": [
        {
            "index": 0,
            "codec_name": "h264",
            "width": 1280,
            "height": 720,
            "resolution": "1280x720",
            "fps": 30.0,
            "pix_fmt": "yuv420p",
        }
    ],
    "audio_streams": [],
    "other_streams": [],
}


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to isolated SQLite."""
    db_url = f"sqlite:///{tmp_path / 'test_adapters.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield vault

    db_mod._engine = None
    db_mod._SessionLocal = None


# ─────────────────────────────────────────────────────────────────────────────
# Adapter Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_generic_media_adapter_supported_extensions():
    adapter = GenericMediaAdapter()
    for ext in [".mp4", ".avi", ".mkv", ".mov", ".ts", ".dav", ".h264", ".h265"]:
        res = adapter.identify(Path(f"test{ext}"))
        assert res.status == "SUPPORTED"
        assert res.confidence == "HIGH"
        assert res.adapter_id == "generic_media"


def test_generic_media_adapter_unsupported():
    adapter = GenericMediaAdapter()
    res = adapter.identify(Path("test.proprietary_raw"))
    assert res.status == "UNSUPPORTED"
    assert res.confidence == "NONE"


def test_generic_media_adapter_capabilities():
    adapter = GenericMediaAdapter()
    caps = adapter.capabilities()
    assert caps.status == "SUPPORTED"
    assert "features" in caps.data
    assert caps.data["features"]["metadata_extraction"] == "TESTED"
    assert len(caps.limitations) > 0


def test_generic_media_extract_metadata_mocked(tmp_path, monkeypatch):
    test_file = tmp_path / "clip.mp4"
    test_file.write_text("dummy")

    adapter = GenericMediaAdapter()
    monkeypatch.setattr(
        "forensiq.adapters.generic_media.run_ffprobe",
        lambda p: {"format": {}, "streams": []},
    )
    monkeypatch.setattr(
        "forensiq.adapters.generic_media.parse_metadata",
        lambda d: SAMPLE_PARSED,
    )

    resp = adapter.extract_metadata(test_file)
    assert resp.status == "SUPPORTED"
    assert resp.data == SAMPLE_PARSED


def test_generic_media_extract_metadata_error(tmp_path, monkeypatch):
    from forensiq.services.metadata_service import MetadataExtractionError
    test_file = tmp_path / "clip.mp4"
    test_file.write_text("dummy")

    adapter = GenericMediaAdapter()

    def _fail(p):
        raise MetadataExtractionError("ffprobe execution failed")

    monkeypatch.setattr("forensiq.adapters.generic_media.run_ffprobe", _fail)

    resp = adapter.extract_metadata(test_file)
    assert resp.status == "FAILED"
    assert "ffprobe execution failed" in resp.error


def test_unknown_source_adapter_safe_failure():
    adapter = UnknownSourceAdapter()
    id_resp = adapter.identify(Path("mystery_dvr.raw"))
    assert id_resp.status == "SAFE_FAILURE"
    assert id_resp.confidence == "NONE"
    assert len(id_resp.limitations) > 0

    meta_resp = adapter.extract_metadata(Path("mystery_dvr.raw"))
    assert meta_resp.status == "SAFE_FAILURE"
    assert meta_resp.confidence == "NONE"


def test_registry_detection():
    registry = AdapterRegistry()
    assert len(registry.list_adapters()) >= 2

    # Should match generic_media for .mp4
    detected = registry.detect_adapter(Path("cam1.mp4"))
    assert detected.ADAPTER_ID == "generic_media"

    # Should match unknown_source fallback for unrecognized extension
    detected_unknown = registry.detect_adapter(Path("stream.xyz_proprietary"))
    assert detected_unknown.ADAPTER_ID == "unknown_source"


# ─────────────────────────────────────────────────────────────────────────────
# Adapter Service Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_adapter_service_working_copy_path(tmp_path):
    vault = tmp_path / "vault"
    with session_scope() as session:
        case = create_case(session, "CASE-AD-001", "Case", investigator_name="Officer")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-010",
            source_filename="footage.mp4",
            sanitized_filename="footage.mp4",
            imported_by="Officer",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        # Create working copy record
        wc_rel = Path("cases") / case.id / "evidence" / item.id / "working_copy" / "footage.mp4"
        wc_abs = vault / wc_rel
        wc_abs.parent.mkdir(parents=True, exist_ok=True)
        wc_abs.write_text("data")

        wc = WorkingCopy(
            evidence_id=item.id,
            relative_path=str(wc_rel),
            sha256="dummy",
            created_at_utc=now_utc(),
            verification_status="VERIFIED",
        )
        session.add(wc)
        session.flush()

        resolved = get_working_copy_path(session, item.id)
        assert resolved == wc_abs
        assert resolved.exists()


def test_analyze_evidence_success(tmp_path, monkeypatch):
    vault = tmp_path / "vault"

    with session_scope() as session:
        case = create_case(session, "CASE-AD-002", "Case", investigator_name="Officer")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-020",
            source_filename="traffic.mp4",
            sanitized_filename="traffic.mp4",
            imported_by="Officer",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        wc_rel = Path("cases") / case.id / "evidence" / item.id / "working_copy" / "traffic.mp4"
        wc_abs = vault / wc_rel
        wc_abs.parent.mkdir(parents=True, exist_ok=True)
        wc_abs.write_text("data")

        wc = WorkingCopy(
            evidence_id=item.id,
            relative_path=str(wc_rel),
            sha256="dummy",
            created_at_utc=now_utc(),
            verification_status="VERIFIED",
        )
        session.add(wc)
        session.flush()

        # Mock adapter response
        monkeypatch.setattr(
            "forensiq.adapters.generic_media.GenericMediaAdapter.extract_metadata",
            lambda self, p: AdapterResponse(
                status="SUPPORTED",
                confidence="HIGH",
                basis="Mocked ffprobe",
                adapter_id="generic_media",
                adapter_version="1.0.0",
                data=SAMPLE_PARSED,
            ),
        )

        resp, records = analyze_evidence(session, item.id, actor_id="Analyst")

        assert resp.status == "SUPPORTED"
        assert len(records) > 0
        assert item.status == EvidenceStatus.ANALYZED.value

        # Verify DB records
        rec = session.query(MetadataRecord).filter_by(evidence_id=item.id, key="format_name").first()
        assert rec is not None
        assert rec.raw_value == "mov,mp4"


def test_analyze_evidence_missing_working_copy():
    with session_scope() as session:
        case = create_case(session, "CASE-AD-003", "Case", investigator_name="Officer")
        item = EvidenceItem(
            case_id=case.id,
            evidence_number="EVD-030",
            source_filename="missing.mp4",
            sanitized_filename="missing.mp4",
            imported_by="Officer",
            imported_at_utc=now_utc(),
        )
        session.add(item)
        session.flush()

        with pytest.raises(FileNotFoundError, match="does not exist"):
            analyze_evidence(session, item.id)
