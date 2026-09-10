"""
tests/test_imaging_service.py
------------------------------
Unit and integration tests for the Forensic Imaging & Acquisition Module.

Tests bit-stream acquisition, simultaneous streaming SHA-256 + MD5 calculation,
independent read-back verification, read-only enforcement, manifest generation,
and custody event recording.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from forensiq.constants import CustodyAction, EvidenceStatus, EvidenceType
from forensiq.database import init_db, session_scope
from forensiq.models.case import Case
from forensiq.models.custody import CustodyEvent
from forensiq.models.evidence import Acquisition, EvidenceItem, WorkingCopy
from forensiq.services.case_service import create_case
from forensiq.services.imaging_service import (
    ImagingError,
    ImagingResult,
    create_forensic_image,
)


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to a fresh SQLite database for each test."""
    db_url = f"sqlite:///{tmp_path / 'test_imaging.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


@pytest.fixture(autouse=True)
def isolate_vault(tmp_path, monkeypatch):
    """Redirect all vault writes to a clean temporary directory."""
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
    yield vault


@pytest.fixture
def active_case() -> str:
    """Create a persistent active case and return its case_id."""
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="CASE-IMG-001",
            title="Physical DVR Seizure Audit",
            investigator_name="Examiner Gupta",
        )
        return case.id


@pytest.fixture
def raw_source_file(tmp_path) -> Path:
    """Create a realistic raw disk exhibit file with arbitrary bytes."""
    source = tmp_path / "seized_dvr_hdd.raw"
    data = b"\xAA\x55\x00\x01\x02\x03\x04\x05" * 4096  # 32 KB
    source.write_bytes(data)
    return source


class TestImagingService:
    """Test suite for forensic disk imaging and verification service."""

    def test_create_forensic_image_success(self, active_case, raw_source_file):
        raw_bytes = raw_source_file.read_bytes()
        expected_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()
        expected_md5 = hashlib.md5(raw_bytes).hexdigest().lower()

        progress_calls = []
        def _on_progress(label: str, done: int, total: int):
            progress_calls.append((label, done, total))

        result = create_forensic_image(
            source_path=raw_source_file,
            case_id=active_case,
            investigator="Examiner Gupta",
            evidence_number="EX-IMG-001",
            description="Seized 500GB Western Digital DVR HDD from crime scene",
            block_size=8192,
            progress_cb=_on_progress,
            simulated_write_blocked=True,
        )

        assert isinstance(result, ImagingResult)
        assert result.evidence_number == "EX-IMG-001"
        assert result.sha256 == expected_sha256
        assert result.md5 == expected_md5
        assert result.file_size_bytes == len(raw_bytes)
        assert result.image_path.exists()
        assert result.working_copy_path.exists()
        assert result.manifest_path.exists()

        # Check read-only attribute on original image
        mode = stat.S_IMODE(os.stat(result.image_path).st_mode)
        # S_IWUSR should be 0 (no write for owner)
        assert not (mode & stat.S_IWUSR)

        # Verify progress callback was triggered
        assert len(progress_calls) > 0
        assert any("Acquiring" in p[0] for p in progress_calls)
        assert any("Verifying" in p[0] for p in progress_calls)

        # Verify manifest content
        manifest_data = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        assert manifest_data["sha256"] == expected_sha256
        assert manifest_data["md5"] == expected_md5
        assert manifest_data["operator"] == "Examiner Gupta"
        assert manifest_data["verification_result"] == "MATCHED"
        assert manifest_data["simulated_write_blocked"] is True

        # Verify database entities & chain of custody events
        with session_scope() as session:
            ev = session.query(EvidenceItem).filter_by(id=result.evidence_id).first()
            assert ev is not None
            assert ev.evidence_type == EvidenceType.DISK_IMAGE.value
            assert ev.original_sha256 == expected_sha256
            assert ev.original_md5 == expected_md5
            assert ev.status == EvidenceStatus.WORKING_COPY_READY.value

            acq = session.query(Acquisition).filter_by(evidence_id=result.evidence_id).first()
            assert acq is not None
            assert acq.method == "FORENSIC_ACQUISITION_SIMULATED_WRITE_BLOCK"

            wc = session.query(WorkingCopy).filter_by(evidence_id=result.evidence_id).first()
            assert wc is not None
            assert wc.sha256 == expected_sha256

            events = (
                session.query(CustodyEvent)
                .filter_by(evidence_id=result.evidence_id)
                .order_by(CustodyEvent.action_timestamp_utc.asc())
                .all()
            )
            action_names = [e.action for e in events]
            assert CustodyAction.IMAGE_CREATED in action_names
            assert CustodyAction.IMAGE_VERIFIED in action_names
            assert CustodyAction.WORKING_COPY_CREATED in action_names
            assert CustodyAction.WORKING_COPY_VERIFIED in action_names

    def test_create_forensic_image_nonexistent_source(self, active_case, tmp_path):
        bad_path = tmp_path / "missing_device.raw"
        with pytest.raises(ImagingError, match="does not exist"):
            create_forensic_image(
                source_path=bad_path,
                case_id=active_case,
                investigator="Examiner Gupta",
            )

    def test_create_forensic_image_empty_source(self, active_case, tmp_path):
        empty_path = tmp_path / "empty_disk.raw"
        empty_path.write_bytes(b"")
        with pytest.raises(ImagingError, match="empty"):
            create_forensic_image(
                source_path=empty_path,
                case_id=active_case,
                investigator="Examiner Gupta",
            )

    def test_create_forensic_image_empty_investigator(self, active_case, raw_source_file):
        with pytest.raises(ImagingError, match="Investigator name must not be empty"):
            create_forensic_image(
                source_path=raw_source_file,
                case_id=active_case,
                investigator="",
            )

    def test_create_forensic_image_custom_block_sizes(self, active_case, raw_source_file):
        raw_bytes = raw_source_file.read_bytes()
        expected_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()

        # Test small block size (512 bytes)
        res = create_forensic_image(
            source_path=raw_source_file,
            case_id=active_case,
            investigator="Examiner Gupta",
            block_size=512,
        )
        assert res.sha256 == expected_sha256
        assert res.block_size == 512

    def test_create_forensic_image_verification_mismatch(self, active_case, raw_source_file, monkeypatch):
        # Corrupt the verify_sha256 calculation to simulate on-disk write corruption
        real_sha256 = hashlib.sha256
        call_count = 0

        class TamperedSha256:
            def __init__(self, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                self._real = real_sha256(*args, **kwargs)
                self._is_verify = (call_count >= 2)

            def update(self, data):
                self._real.update(data)

            def hexdigest(self):
                if self._is_verify:
                    return "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
                return self._real.hexdigest()

        monkeypatch.setattr(hashlib, "sha256", TamperedSha256)

        with pytest.raises(ImagingError, match="verification failed"):
            create_forensic_image(
                source_path=raw_source_file,
                case_id=active_case,
                investigator="Examiner Gupta",
            )
