"""
tests/test_recovery.py
----------------------
Unit and integration tests for surveillance video carving, Annex-B NAL unit reconstruction,
derivative manifest creation, and custody ledger integration.

Phase 7: Fully implemented.
"""

import json
from pathlib import Path

import pytest

from forensiq.constants import CustodyAction, EvidenceStatus, RecoveryStatus
from forensiq.database import init_db, session_scope
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.recovery import RecoveryResult
from forensiq.services.case_service import create_case
from forensiq.services.custody_service import get_chain_for_case
from forensiq.services.recovery_service import (
    MANDATORY_RECOVERY_WARNING,
    RECOVERY_TIER_1_FS_INDEX,
    RECOVERY_TIER_2_STREAM_CARVING,
    carve_video_stream,
    list_recovery_results_for_evidence,
    scan_annex_b_nalus,
    scan_dhfs_index_entries,
)
from forensiq.utils.hashing import hash_file
from forensiq.utils.utc_utils import now_utc


@pytest.fixture(autouse=True)
def isolate_env(tmp_path, monkeypatch):
    """Isolate DB and Vault paths for each test."""
    db_url = f"sqlite:///{tmp_path / 'test_recovery.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault_dir)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


class TestScanAnnexBNALUs:
    """Tests for raw byte-level NAL unit scanner."""

    def test_scan_h264_parameter_sets_and_slices(self):
        # Synthetic Annex-B stream
        stream = (
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"  # SPS (type 7)
            b"\x00\x00\x00\x01\x68\xce\x3c\x80"      # PPS (type 8)
            b"\x00\x00\x00\x01\x65\x88\x84\xff"      # IDR Keyframe (type 5)
            b"\x00\x00\x01\x41\x9a\x00\x02"          # Non-IDR Slice (type 1)
        )
        nalus = scan_annex_b_nalus(stream)

        assert len(nalus) == 4
        assert nalus[0]["is_sps"] is True
        assert nalus[0]["h264_type"] == 7
        assert nalus[1]["is_pps"] is True
        assert nalus[1]["h264_type"] == 8
        assert nalus[2]["is_idr"] is True
        assert nalus[2]["is_slice"] is True
        assert nalus[3]["is_slice"] is True
        assert nalus[3]["header_len"] == 3

    def test_scan_h265_parameter_sets(self):
        # Synthetic H.265 VPS (type 32) and SPS (type 33)
        stream = (
            b"\x00\x00\x00\x01\x40\x01\x0c\x01"  # VPS: (0x40 >> 1) & 0x3F == 32
            b"\x00\x00\x00\x01\x42\x01\x01\x01"  # SPS: (0x42 >> 1) & 0x3F == 33
        )
        nalus = scan_annex_b_nalus(stream)

        assert len(nalus) == 2
        assert nalus[0]["h265_type"] == 32
        assert nalus[1]["h265_type"] == 33
        assert nalus[1]["is_sps"] is True

    def test_scan_short_or_empty_input(self):
        assert scan_annex_b_nalus(b"") == []
        assert scan_annex_b_nalus(b"\x00\x00\x00") == []
        assert scan_annex_b_nalus(b"RANDOM_NON_VIDEO_DATA") == []


@pytest.fixture
def evidence_fixture(tmp_path):
    """Fixture creating a case, evidence item, and working copy directory."""
    with session_scope() as session:
        case = create_case(session, "CASE-RECOVERY-001", "Recovery Test Case", "Investigator A")
        case_id = case.id

        ev = EvidenceItem(
            case_id=case_id,
            evidence_number="EX-CARVE-01",
            source_filename="damaged_dvr.raw",
            sanitized_filename="damaged_dvr.raw",
            file_size_bytes=4096,
            original_sha256="2222222222222222222222222222222222222222222222222222222222222222",
            status=EvidenceStatus.WORKING_COPY_READY.value,
            imported_by="Investigator A",
            imported_at_utc=now_utc(),
        )
        session.add(ev)
        session.flush()

        # Create working copy file on disk
        wc_dir = tmp_path / "vault" / case_id / "evidence" / ev.id / "working_copy"
        wc_dir.mkdir(parents=True, exist_ok=True)
        wc_file = wc_dir / "damaged_dvr.raw"
        wc_file.write_bytes(b"INITIAL_WC_PLACEHOLDER")

        wc = WorkingCopy(
            evidence_id=ev.id,
            relative_path=str(wc_file.relative_to(tmp_path / "vault")),
            sha256="2222222222222222222222222222222222222222222222222222222222222222",
            created_at_utc=now_utc(),
            verification_status="VERIFIED",
        )
        session.add(wc)
        session.commit()

        return case_id, ev.id, wc_file


class TestCarveVideoStream:
    """Integration test suite for video stream carving."""

    def test_carve_complete_stream(self, evidence_fixture):
        case_id, ev_id, wc_file = evidence_fixture

        # Populate working copy with corrupt noise prefix, then valid SPS/PPS/IDR + slices
        valid_stream = (
            b"CORRUPT_FILESYSTEM_SECTOR_NOISE_XXXXXX\x00\xff"  # Corrupt prefix
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"           # SPS
            b"\x00\x00\x00\x01\x68\xce\x3c\x80"               # PPS
            b"\x00\x00\x00\x01\x65\x88\x84\x00\x10\xff"       # IDR Keyframe
            b"\x00\x00\x01\x41\x9a\x00\x02\x01"               # Slice 1
            b"\x00\x00\x01\x41\x9a\x00\x02\x02"               # Slice 2
            b"\x00\x00\x01\x41\x9a\x00\x02\x03"               # Slice 3
            b"\x00\x00\x01\x41\x9a\x00\x02\x04"               # Slice 4
            b"\x00\x00\x01\x41\x9a\x00\x02\x05"               # Slice 5
        )
        wc_file.write_bytes(valid_stream)

        with session_scope() as session:
            rec_res, derivative_path = carve_video_stream(
                session=session,
                evidence_id=ev_id,
                actor_id="Analyst J",
            )

            assert rec_res is not None
            assert rec_res.status == RecoveryStatus.COMPLETE.value
            assert rec_res.confidence == "HIGH"
            assert derivative_path is not None
            assert derivative_path.exists()
            assert derivative_path.suffix == ".h264"

            # Verify derivative contents excluded the corrupt prefix
            derivative_bytes = derivative_path.read_bytes()
            assert b"CORRUPT_FILESYSTEM_SECTOR_NOISE" not in derivative_bytes
            assert derivative_bytes.startswith(b"\x00\x00\x00\x01\x67")  # Starts at SPS

            # Verify SHA-256 matches
            computed_sha = hash_file(derivative_path).sha256
            assert rec_res.sha256 == computed_sha

            # Verify companion manifest
            manifest_path = derivative_path.with_name(f"{derivative_path.name}.manifest.json")
            assert manifest_path.exists()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            assert manifest["sha256"] == computed_sha
            assert manifest["sps_count"] == 1
            assert manifest["pps_count"] == 1
            assert manifest["idr_count"] == 1

            # Verify custody ledger
            events = get_chain_for_case(session, case_id)
            actions = [e.action for e in events]
            assert CustodyAction.RECOVERY_ATTEMPTED.value in actions
            assert CustodyAction.DERIVATIVE_CREATED.value in actions

            deriv_event = [e for e in events if e.action == CustodyAction.DERIVATIVE_CREATED.value][0]
            assert deriv_event.output_sha256 == computed_sha

    def test_carve_unrecoverable_garbage(self, evidence_fixture):
        case_id, ev_id, wc_file = evidence_fixture

        # Write unrecoverable random text
        wc_file.write_text("PLAIN_TEXT_NON_VIDEO_FILE_CONTENT", encoding="utf-8")

        with session_scope() as session:
            rec_res, derivative_path = carve_video_stream(
                session=session,
                evidence_id=ev_id,
                actor_id="Analyst J",
            )

            assert rec_res.status == RecoveryStatus.UNRECOVERABLE.value
            assert rec_res.confidence == "NONE"
            assert derivative_path is None
            assert MANDATORY_RECOVERY_WARNING in rec_res.limitations

            # Custody event still recorded for the attempt
            events = get_chain_for_case(session, case_id)
            attempt_event = [e for e in events if e.action == CustodyAction.RECOVERY_ATTEMPTED.value]
            assert len(attempt_event) == 1

    def test_missing_working_copy_raises(self, evidence_fixture):
        case_id, ev_id, wc_file = evidence_fixture
        wc_file.unlink()  # delete from disk

        with session_scope() as session:
            with pytest.raises(FileNotFoundError, match="not found on disk"):
                carve_video_stream(session, ev_id)

    def test_missing_evidence_raises(self):
        with session_scope() as session:
            with pytest.raises(ValueError, match="not found"):
                carve_video_stream(session, "NON-EXISTENT-ID")

    def test_list_recovery_results(self, evidence_fixture):
        case_id, ev_id, wc_file = evidence_fixture
        wc_file.write_bytes(b"\x00\x00\x01\x65\x88\x84")  # Partial IDR

        with session_scope() as session:
            carve_video_stream(session, ev_id)
            results = list_recovery_results_for_evidence(session, ev_id)
            assert len(results) >= 1
            assert results[0].method == "ANNEX_B_NALU_CARVER"

    def test_scan_dhfs_index_entries(self):
        import struct
        # Construct synthetic DHFS index entry (channel 4, start_ts=1700000000, offset=128, len=512, deleted=True)
        dhfs_entry = (
            b"DHFS"
            + struct.pack("<H", 4)
            + struct.pack("<I", 1700000000)
            + struct.pack("<I", 1700000300)
            + struct.pack("<I", 128)
            + struct.pack("<I", 512)
            + struct.pack("<B", 0x02)  # Deleted flag
            + b"\x00"                  # Padding to 24 bytes
        )
        buffer = dhfs_entry + (b"\x00" * 1024)

        entries = scan_dhfs_index_entries(buffer)
        assert len(entries) == 1
        assert entries[0]["channel_id"] == 4
        assert entries[0]["start_timestamp"] == 1700000000
        assert entries[0]["data_offset"] == 128
        assert entries[0]["data_length"] == 512
        assert entries[0]["is_deleted"] is True

    def test_tier1_dhfs_filesystem_index_recovery(self, evidence_fixture):
        import struct
        case_id, ev_id, wc_file = evidence_fixture

        # Video chunk to place at offset 64
        video_payload = (
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"           # SPS
            b"\x00\x00\x00\x01\x68\xce\x3c\x80"               # PPS
            b"\x00\x00\x00\x01\x65\x88\x84\x00\x10\xff"       # IDR Keyframe
            b"\x00\x00\x01\x41\x9a\x00\x02\x01"               # Slice
        )
        offset = 64
        length = len(video_payload)

        # 24-byte DHFS entry at start
        dhfs_table = (
            b"DHFS"
            + struct.pack("<H", 2)               # Channel 2
            + struct.pack("<I", 1760000000)      # Start time
            + struct.pack("<I", 1760000060)      # End time
            + struct.pack("<I", offset)          # Data offset
            + struct.pack("<I", length)          # Data length
            + struct.pack("<B", 0x02)            # Flag: deleted recording
            + b"\x00"
        )
        padding = b"\xaa" * (offset - len(dhfs_table))
        full_disk_image = dhfs_table + padding + video_payload + (b"\xff" * 128)
        wc_file.write_bytes(full_disk_image)

        with session_scope() as session:
            rec_res, derivative_path = carve_video_stream(
                session=session,
                evidence_id=ev_id,
                actor_id="Investigator DHFS",
            )

            assert rec_res is not None
            assert rec_res.status == RecoveryStatus.COMPLETE.value
            assert rec_res.confidence == "HIGH"
            assert rec_res.method == "TIER_1_DHFS_INDEX_RECOVERY"
            assert derivative_path is not None
            assert derivative_path.exists()
            assert derivative_path.name.startswith("tier1_fs_")

            # Check manifest records Tier 1 and filesystem metadata
            manifest_path = derivative_path.with_name(f"{derivative_path.name}.manifest.json")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            assert manifest["recovery_tier"] == RECOVERY_TIER_1_FS_INDEX
            assert manifest["filesystem_type"] == "DHFS"
            assert manifest["channel_id"] == 2
            assert manifest["is_deleted"] is True

            # Verify custody ledger records Tier 1
            events = get_chain_for_case(session, case_id)
            attempt = [e for e in events if e.action == CustodyAction.RECOVERY_ATTEMPTED.value][0]
            details = json.loads(attempt.details_json) if attempt.details_json else {}
            assert details.get("recovery_tier") == RECOVERY_TIER_1_FS_INDEX
            assert "Tier 1 DHFS" in attempt.reason
