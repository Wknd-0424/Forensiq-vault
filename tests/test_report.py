"""
tests/test_report.py
--------------------
Comprehensive tests for Forensic Reporting Engine & Court-Admissible Dossier Generation.

Tests:
  - HTML report rendering with embedded Section 65B certificate & print styles.
  - JSON dossier generation with full schema conformity.
  - PDF generation via PySide6 QTextDocument & QPdfWriter.
  - Companion .manifest.json generation and SHA-256 verification.
  - CustodyAction.REPORT_GENERATED event recording in the immutable hash chain.
  - Report integrity checking (tamper detection).
  - Listing reports for a case.

Phase 6: Fully implemented.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forensiq.constants import (
    AnalystStatus,
    CustodyAction,
    EvidenceStatus,
    ReviewerStatus,
    TimelineEventType,
)
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.models.detection import AIDetection
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.report import Report
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.models.validation import ValidationRun
from forensiq.services.case_service import create_case
from forensiq.services.custody_service import get_chain_for_case, verify_chain
from forensiq.services.report_service import (
    generate_forensic_report,
    get_report_by_id,
    list_reports_for_case,
    verify_report_integrity,
)
from forensiq.utils.hashing import hash_file
from forensiq.utils.utc_utils import now_utc


@pytest.fixture(autouse=True)
def isolate_env(tmp_path, monkeypatch):
    """Isolate DB and Vault paths for each test."""
    db_url = f"sqlite:///{tmp_path / 'test_report.db'}"
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


@pytest.fixture
def populated_case():
    """Create a fully populated case with exhibits, metadata, validation, timeline, and AI triage."""
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="CASE-2026-REPORT-001",
            title="Court Admissibility Test Case",
            investigator_name="Inspector R. Sharma",
        )
        case.description = "Surveillance investigation testing Section 65B compliance."
        case_id = case.id

        # Exhibit 1
        ev1 = EvidenceItem(
            case_id=case_id,
            evidence_number="EX-001",
            source_filename="cctv_entrance_cam01.mp4",
            sanitized_filename="cctv_entrance_cam01.mp4",
            file_size_bytes=10485760,  # 10 MB
            original_sha256="1111111111111111111111111111111111111111111111111111111111111111",
            original_md5="11111111111111111111111111111111",
            status=EvidenceStatus.ANALYZED.value,
            imported_by="Inspector R. Sharma",
            imported_at_utc=now_utc(),
        )
        session.add(ev1)
        session.flush()

        # Metadata records for ev1
        md1 = MetadataRecord(
            evidence_id=ev1.id,
            namespace="ffprobe",
            key="format_name",
            raw_value="mov,mp4,m4a,3gp",
            normalized_value="mp4",
        )
        md2 = MetadataRecord(
            evidence_id=ev1.id,
            namespace="ffprobe",
            key="codec_name",
            raw_value="h264",
            normalized_value="h264",
        )
        md3 = MetadataRecord(
            evidence_id=ev1.id,
            namespace="ffprobe",
            key="resolution",
            raw_value="1920x1080",
            normalized_value="1920x1080",
        )
        md4 = MetadataRecord(
            evidence_id=ev1.id,
            namespace="ffprobe",
            key="fps",
            raw_value="25.0",
            normalized_value="25.0",
        )
        session.add_all([md1, md2, md3, md4])

        # Validation run for ev1
        val_checks = [
            {"check": "Container & Codec Alignment", "status": "PASSED", "message": "Valid h264 in mp4."},
            {"check": "Timestamp Sanity", "status": "PASSED", "message": "Timestamps are rational."},
        ]
        val_run = ValidationRun(
            evidence_id=ev1.id,
            validation_type="FORENSIC_SANITY_SUITE",
            status="PASSED",
            results_json=json.dumps(val_checks),
            performed_by="Inspector R. Sharma",
            performed_at_utc=now_utc(),
            tool_version="0.1.0",
        )
        session.add(val_run)

        # Timeline event
        te1 = TimelineEvent(
            case_id=case_id,
            evidence_id=ev1.id,
            raw_timestamp="2026-03-01 14:30:00",
            normalized_timestamp_utc=datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc),
            offset_seconds=-19800.0,
            event_type=TimelineEventType.METADATA.value,
            description="Camera recording initialized.",
            analyst_status=AnalystStatus.CONFIRMED.value,
        )
        session.add(te1)

        # Video Segment & AI Detection
        seg1 = VideoSegment(
            evidence_id=ev1.id,
            channel_id="CH01",
            duration_seconds=60.0,
            codec="h264",
            resolution="1920x1080",
            frame_rate="25.0",
        )
        session.add(seg1)
        session.flush()

        det1 = AIDetection(
            segment_id=seg1.id,
            frame_number=150,
            frame_timestamp="00:00:06.000",
            class_name="person",
            confidence=0.92,
            bbox_json=json.dumps([0.2, 0.3, 0.15, 0.4]),
            threshold=0.6,
            model_name="Local-Heuristic-Engine",
            model_version="1.0.0",
            reviewer_status=ReviewerStatus.CONFIRMED.value,
            reviewer_id="Inspector R. Sharma",
            reviewed_at_utc=now_utc(),
        )
        session.add(det1)
        session.commit()

        return case_id


def test_generate_html_report(populated_case):
    """Test generating a court-admissible HTML report."""
    with session_scope() as session:
        report, report_path = generate_forensic_report(
            session=session,
            case_id=populated_case,
            report_format="HTML",
            actor_id="Inspector R. Sharma",
        )

        assert report is not None
        assert report.report_type == "HTML"
        assert report_path.exists()
        assert report_path.suffix == ".html"

        content = report_path.read_text(encoding="utf-8")

        # Verify key forensic elements in HTML
        assert "FORENSIQ VAULT — DIGITAL FORENSIC DOSSIER" in content
        assert "CASE-2026-REPORT-001" in content
        assert "Court Admissibility Test Case" in content
        assert "Inspector R. Sharma" in content
        assert "Section 65B of the Indian Evidence Act, 1872" in content
        assert "Section 63, Bharatiya Sakshya Adhiniyam, 2023" in content
        assert "EX-001" in content
        assert "cctv_entrance_cam01.mp4" in content
        assert "1920x1080" in content
        assert "MANDATORY FORENSIC DISCLAIMER" in content
        assert "Biometric facial recognition is strictly prohibited" in content

        # Verify manifest
        manifest_path = report_path.with_name(f"{report_path.name}.manifest.json")
        assert manifest_path.exists()
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest_data["report_file"] == report_path.name
        assert manifest_data["sha256"] == report.sha256

        # Verify chain of custody logged REPORT_GENERATED
        events = get_chain_for_case(session, populated_case)
        report_events = [e for e in events if e.action == CustodyAction.REPORT_GENERATED.value]
        assert len(report_events) == 1
        assert report_events[0].output_sha256 == report.sha256


def test_generate_json_dossier(populated_case):
    """Test generating a structured JSON dossier for automated court records."""
    with session_scope() as session:
        report, report_path = generate_forensic_report(
            session=session,
            case_id=populated_case,
            report_format="JSON",
            actor_id="Inspector R. Sharma",
        )

        assert report.report_type == "JSON"
        assert report_path.suffix == ".json"

        dossier = json.loads(report_path.read_text(encoding="utf-8"))

        # Check required schema sections
        assert "dossier_metadata" in dossier
        assert "case_details" in dossier
        assert "custody_audit" in dossier
        assert "evidence_inventory" in dossier
        assert "stream_analysis" in dossier
        assert "timeline_events" in dossier
        assert "ai_detections" in dossier
        assert "legal_compliance" in dossier

        assert dossier["case_details"]["case_number"] == "CASE-2026-REPORT-001"
        assert len(dossier["evidence_inventory"]) == 1
        assert dossier["evidence_inventory"][0]["evidence_number"] == "EX-001"
        assert len(dossier["stream_analysis"]) == 1
        assert dossier["stream_analysis"][0]["resolution"] == "1920x1080"
        assert len(dossier["ai_detections"]) == 1
        assert dossier["ai_detections"][0]["class_name"] == "person"
        assert dossier["legal_compliance"]["certified_by"] == "Inspector R. Sharma"


def test_generate_pdf_report(populated_case):
    """Test generating a PDF report via PySide6."""
    with session_scope() as session:
        report, report_path = generate_forensic_report(
            session=session,
            case_id=populated_case,
            report_format="PDF",
            actor_id="Inspector R. Sharma",
        )

        assert report.report_type == "PDF"
        assert report_path.suffix == ".pdf"
        assert report_path.exists()
        assert report_path.stat().st_size > 1000

        # Read binary header
        with open(report_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"


def test_verify_report_integrity(populated_case, tmp_path):
    """Test verification of report hash against stored database hash."""
    with session_scope() as session:
        report, report_path = generate_forensic_report(
            session=session,
            case_id=populated_case,
            report_format="HTML",
        )
        report_id = report.id

        # 1. Unaltered file should verify
        is_valid, msg = verify_report_integrity(session, report_id)
        assert is_valid is True
        assert "intact" in msg.lower()

        # 2. Tamper with file
        with open(report_path, "a", encoding="utf-8") as f:
            f.write("\n<!-- MALICIOUS ALTERATION -->")

        is_valid_tampered, msg_tampered = verify_report_integrity(session, report_id)
        assert is_valid_tampered is False
        assert "mismatch" in msg_tampered.lower() or "violation" in msg_tampered.lower()

        # 3. Deleted file
        report_path.unlink()
        is_valid_deleted, msg_deleted = verify_report_integrity(session, report_id)
        assert is_valid_deleted is False
        assert "missing" in msg_deleted.lower()


def test_list_reports_for_case(populated_case):
    """Test querying all reports generated for a case."""
    with session_scope() as session:
        rep1, _ = generate_forensic_report(session, populated_case, "HTML")
        rep2, _ = generate_forensic_report(session, populated_case, "JSON")

        reports = list_reports_for_case(session, populated_case)
        assert len(reports) == 2
        report_types = {r.report_type for r in reports}
        assert report_types == {"HTML", "JSON"}


def test_invalid_parameters(populated_case):
    """Test validation errors for missing case or unsupported format."""
    with session_scope() as session:
        with pytest.raises(ValueError, match="not found"):
            generate_forensic_report(session, "NON-EXISTENT-CASE-ID", "HTML")

        with pytest.raises(ValueError, match="Unsupported report format"):
            generate_forensic_report(session, populated_case, "DOCX")
