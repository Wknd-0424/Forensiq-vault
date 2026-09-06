"""
tests/test_e2e_smoke.py
-----------------------
End-to-end integration smoke test exercising the complete forensic pipeline:
  1. Case creation
  2. Multi-vendor sample evidence import & hashing
  3. Working copy creation & read-only lock
  4. Adapter detection & profile syncing
  5. Video stream carving on damaged evidence
  6. Timeline event creation & offset normalization
  7. AI triage with analyst confirmation
  8. Chain of custody verification
  9. Court-admissible forensic report generation (HTML + JSON + PDF)
"""

from pathlib import Path
import pytest

from forensiq.adapters.registry import get_registry, sync_adapter_profiles
from forensiq.constants import ChainVerificationResult, CustodyAction, EvidenceStatus, RecoveryStatus
from forensiq.database import init_db, session_scope
from forensiq.services.case_service import create_case
from forensiq.services.evidence_service import import_evidence
from forensiq.services.custody_service import verify_chain, get_chain_for_case
from forensiq.services.recovery_service import carve_video_stream
from forensiq.services.timeline_service import (
    create_or_update_segment_from_evidence,
    apply_timestamp_normalization,
)
from forensiq.services.ai_service import run_ai_triage, review_detection
from forensiq.services.report_service import generate_forensic_report, verify_report_integrity


@pytest.fixture(autouse=True)
def isolated_smoke_env(tmp_path, monkeypatch):
    """Isolate DB and Vault paths for the end-to-end smoke test."""
    db_url = f"sqlite:///{tmp_path / 'smoke_test.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault_dir)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    with session_scope() as session:
        sync_adapter_profiles(session)

    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


def test_complete_forensic_lifecycle(tmp_path):
    """Exercise complete evidence lifecycle from case creation to court report."""
    sample_dir = Path(__file__).resolve().parent.parent / "sample_evidence"
    dahua_file = sample_dir / "EX01_Dahua_CAM01_Entrance.dav"
    damaged_file = sample_dir / "EX04_Damaged_DVR_Carve_Target.raw"

    assert dahua_file.exists(), "Sample Dahua exhibit missing"
    assert damaged_file.exists(), "Sample Damaged exhibit missing"

    # 1. Create Case
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="SIH-2026-NTRO-001",
            title="Operation CyberShield Surveillance Audit",
            investigator_name="Forensic Examiner Sharma",
            authority_reference="National Technical Research Organisation (NTRO)",
        )
        case_id = case.id

    # 2. Import Dahua Evidence
    res1 = import_evidence(
        case_id=case_id,
        source_path=dahua_file,
        evidence_number="EX-01-DAHUA",
        investigator="Forensic Examiner Sharma",
        description="Dahua CCTV capture at Perimeter Gate 1",
    )
    assert res1.evidence_id is not None
    assert res1.original_sha256 is not None
    ev1_id = res1.evidence_id

    # 3. Detect Adapter
    registry = get_registry()
    adapter1 = registry.detect_adapter(dahua_file)
    assert adapter1.ADAPTER_ID == "dahua_export"

    # 4. Import Damaged Evidence
    res2 = import_evidence(
        case_id=case_id,
        source_path=damaged_file,
        evidence_number="EX-02-DAMAGED",
        investigator="Forensic Examiner Sharma",
        description="Carved disk image from water-damaged DVR",
    )
    assert res2.evidence_id is not None
    ev2_id = res2.evidence_id

    with session_scope() as session:
        # 5. Carve Video Stream on Damaged Working Copy
        rec_res, deriv_path = carve_video_stream(
            session=session,
            evidence_id=ev2_id,
            actor_id="Forensic Examiner Sharma",
        )
        assert rec_res.status == RecoveryStatus.COMPLETE.value
        assert deriv_path is not None
        assert deriv_path.exists()

        # 6. Timeline & Normalization
        segment = create_or_update_segment_from_evidence(session, ev1_id)
        assert segment is not None

        apply_timestamp_normalization(
            session=session,
            evidence_id=ev1_id,
            offset_seconds=120.0,
            reason="DVR clock was 2 minutes behind NTP reference",
            actor_id="Forensic Examiner Sharma",
        )

        # 7. AI Triage & Analyst Review
        detections = run_ai_triage(
            session=session,
            segment_id=segment.id,
            actor_id="Forensic Examiner Sharma",
        )
        assert len(detections) >= 1
        review_detection(
            session=session,
            detection_id=detections[0].id,
            reviewer_status="CONFIRMED",
            notes="Verified unauthorized vehicle movement near gate.",
            reviewer_id="Forensic Examiner Sharma",
        )

        # 8. Cryptographic Chain of Custody Audit
        chain_res, errors = verify_chain(session, case_id)
        assert chain_res == ChainVerificationResult.VALID
        assert len(errors) == 0

        # 9. Generate Section 65B/63 Certified Forensic Dossiers
        html_report, html_path = generate_forensic_report(
            session=session,
            case_id=case_id,
            report_format="HTML",
            actor_id="Forensic Examiner Sharma",
        )
        assert html_path.exists()
        is_valid_html, _ = verify_report_integrity(session, html_report.id)
        assert is_valid_html is True

        json_report, json_path = generate_forensic_report(
            session=session,
            case_id=case_id,
            report_format="JSON",
            actor_id="Forensic Examiner Sharma",
        )
        assert json_path.exists()
        is_valid_json, _ = verify_report_integrity(session, json_report.id)
        assert is_valid_json is True

        pdf_report, pdf_path = generate_forensic_report(
            session=session,
            case_id=case_id,
            report_format="PDF",
            actor_id="Forensic Examiner Sharma",
        )
        assert pdf_path.exists()
        is_valid_pdf, _ = verify_report_integrity(session, pdf_report.id)
        assert is_valid_pdf is True
