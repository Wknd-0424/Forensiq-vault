"""
forensiq/services/report_service.py
------------------------------------
Forensic Reporting Engine & Court-Admissible Dossier Generation.

Generates legally compliant, court-admissible forensic dossiers in HTML,
JSON, and PDF formats.

Key Forensic Deliverables:
  1. Executive Summary & Case Details
  2. Vaulted Evidence Inventory & Integrity Verification (with working copy status)
  3. Video Stream & Forensic Sanity Analysis (codecs, resolutions, sanity checks)
  4. Chronological Multi-Camera Timeline (normalized UTC + raw device time)
  5. AI-Assisted Triage & Anomaly Findings (mandatory disclaimer, reviewer flags)
  6. Cryptographic Chain of Custody Audit Ledger (sequential SHA-256 links)
  7. Section 65B Indian Evidence Act / Section 63 BSA Legal Certificate
  8. Atomic report hashing and manifest generation with custody event logging.

Phase 6: Fully implemented.
"""

import hashlib
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

import forensiq.config as _cfg
from forensiq.config import TOOL_VERSION
from forensiq.constants import ChainVerificationResult, CustodyAction
from forensiq.models.case import Case
from forensiq.models.custody import CustodyEvent
from forensiq.models.detection import AIDetection
from forensiq.models.evidence import EvidenceItem
from forensiq.models.metadata import MetadataRecord
from forensiq.models.report import Report
from forensiq.models.timeline import TimelineEvent, VideoSegment
from forensiq.models.validation import ValidationRun
from forensiq.services.custody_service import get_chain_for_case, record_event, verify_chain
from forensiq.utils.hashing import hash_file
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def _get_jinja_env() -> Environment:
    """Initialize and return the Jinja2 template environment."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def _collect_report_data(session: Session, case_id: str, actor_id: str = "Investigator") -> dict[str, Any]:
    """
    Gather and structure all case data, exhibits, stream metadata,
    validation runs, timeline events, AI triage detections, and custody ledger.
    """
    case = session.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise ValueError(f"Case with ID '{case_id}' was not found in the database.")

    evidence_items = (
        session.query(EvidenceItem)
        .filter(EvidenceItem.case_id == case_id)
        .order_by(EvidenceItem.evidence_number.asc())
        .all()
    )

    # Chain of custody verification & events
    custody_events_raw = get_chain_for_case(session, case_id)
    chain_result, chain_errors = verify_chain(session, case_id)
    if chain_result == ChainVerificationResult.VALID:
        chain_status = "INTACT"
    elif chain_result == ChainVerificationResult.EMPTY_CHAIN:
        chain_status = "EMPTY"
    else:
        chain_status = "COMPROMISED"

    # Multi-camera timeline
    timeline_events_raw = (
        session.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.normalized_timestamp_utc.asc())
        .all()
    )

    # AI detections
    ai_detections_raw = (
        session.query(AIDetection)
        .join(VideoSegment, AIDetection.segment_id == VideoSegment.id)
        .join(EvidenceItem, VideoSegment.evidence_id == EvidenceItem.id)
        .filter(EvidenceItem.case_id == case_id)
        .order_by(AIDetection.frame_number.asc())
        .all()
    )

    # Stream metadata & validation runs per exhibit
    evidence_analysis = []
    for ev in evidence_items:
        records = session.query(MetadataRecord).filter(MetadataRecord.evidence_id == ev.id).all()
        md_dict = {r.key: (r.normalized_value or r.raw_value) for r in records}

        # Resolution extraction
        resolution = md_dict.get("resolution")
        if not resolution and "width" in md_dict and "height" in md_dict:
            resolution = f"{md_dict['width']}x{md_dict['height']}"

        # Validation sanity checks
        val_run = (
            session.query(ValidationRun)
            .filter(ValidationRun.evidence_id == ev.id)
            .order_by(ValidationRun.performed_at_utc.desc())
            .first()
        )
        val_checks = []
        if val_run and val_run.results_json:
            try:
                val_checks = json.loads(val_run.results_json)
            except Exception as exc:
                logger.warning("Failed parsing validation JSON for evidence %s: %s", ev.id, exc)

        evidence_analysis.append({
            "evidence": ev,
            "format_name": md_dict.get("format_name") or md_dict.get("container_format") or "Unknown",
            "duration": md_dict.get("duration") or md_dict.get("duration_seconds") or "N/A",
            "bit_rate": md_dict.get("bit_rate") or md_dict.get("bitrate") or "N/A",
            "codec": md_dict.get("codec_name") or md_dict.get("video_codec") or "N/A",
            "resolution": resolution or "N/A",
            "fps": md_dict.get("fps") or md_dict.get("frame_rate") or "N/A",
            "validation_checks": val_checks,
        })

    # Prepare template-friendly serializations
    custody_events_data = [
        {
            "sequence_number": i + 1,
            "timestamp_utc": to_iso8601(ce.action_timestamp_utc),
            "action": ce.action,
            "actor_id": ce.actor_id or "—",
            "previous_event_hash": ce.previous_event_hash or "GENESIS",
            "event_hash": ce.event_hash,
        }
        for i, ce in enumerate(custody_events_raw)
    ]

    timeline_events_data = [
        {
            "normalized_utc": to_iso8601(te.normalized_timestamp_utc) if te.normalized_timestamp_utc else "—",
            "raw_timestamp": te.raw_timestamp or "—",
            "offset_seconds": te.offset_seconds,
            "event_type": te.event_type,
            "analyst_status": te.analyst_status,
            "description": te.description,
        }
        for te in timeline_events_raw
    ]

    return {
        "case": case,
        "chain_status": chain_status,
        "chain_result": chain_result,
        "chain_errors": chain_errors,
        "evidence_items": evidence_items,
        "evidence_analysis": evidence_analysis,
        "custody_events_raw": custody_events_raw,
        "custody_events": custody_events_data,
        "timeline_events_raw": timeline_events_raw,
        "timeline_events": timeline_events_data,
        "ai_detections": ai_detections_raw,
    }


def _render_html_report(data: dict[str, Any], timestamp_str: str) -> str:
    """Render the forensic_report.html Jinja2 template with case context."""
    env = _get_jinja_env()
    template = env.get_template("forensic_report.html")
    context = {
        "case": data["case"],
        "chain_status": data["chain_status"],
        "generated_at_utc": timestamp_str,
        "tool_name": "ForensIQ Vault",
        "tool_version": TOOL_VERSION,
        "evidence_items": data["evidence_items"],
        "evidence_analysis": data["evidence_analysis"],
        "timeline_events": data["timeline_events"],
        "ai_detections": data["ai_detections"],
        "custody_events": data["custody_events"],
    }
    return template.render(**context)


def _render_json_dossier(data: dict[str, Any], timestamp_str: str, actor_id: str) -> str:
    """Generate the full, structured JSON dossier for automated court data interchange."""
    case = data["case"]
    dossier = {
        "dossier_metadata": {
            "schema_version": "1.0.0",
            "tool_name": "ForensIQ Vault",
            "tool_version": TOOL_VERSION,
            "generated_at_utc": timestamp_str,
            "generated_by": actor_id,
            "report_type": "JSON_DOSSIER",
        },
        "case_details": {
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "created_by": case.created_by,
            "authority_reference": case.authority_reference,
            "description": case.description,
            "created_at_utc": to_iso8601(case.created_at_utc),
            "status": case.status,
        },
        "custody_audit": {
            "chain_status": data["chain_status"],
            "verification_result": data["chain_result"].value,
            "verification_errors": data["chain_errors"],
            "total_events": len(data["custody_events_raw"]),
            "genesis_event_hash": (
                data["custody_events_raw"][0].event_hash
                if data["custody_events_raw"]
                else None
            ),
            "latest_event_hash": (
                data["custody_events_raw"][-1].event_hash
                if data["custody_events_raw"]
                else None
            ),
            "events": [
                {
                    "sequence": i + 1,
                    "id": ce.id,
                    "action": ce.action,
                    "timestamp_utc": to_iso8601(ce.action_timestamp_utc),
                    "actor": ce.actor_id,
                    "evidence_id": ce.evidence_id,
                    "reason": ce.reason,
                    "input_sha256": ce.input_sha256,
                    "output_sha256": ce.output_sha256,
                    "previous_event_hash": ce.previous_event_hash,
                    "event_hash": ce.event_hash,
                }
                for i, ce in enumerate(data["custody_events_raw"])
            ],
        },
        "evidence_inventory": [
            {
                "id": ev.id,
                "evidence_number": ev.evidence_number,
                "source_filename": ev.source_filename,
                "file_size_bytes": ev.file_size_bytes,
                "original_sha256": ev.original_sha256,
                "original_md5": ev.original_md5,
                "imported_at_utc": to_iso8601(ev.imported_at_utc),
                "status": ev.status,
            }
            for ev in data["evidence_items"]
        ],
        "stream_analysis": [
            {
                "evidence_number": item["evidence"].evidence_number,
                "source_filename": item["evidence"].source_filename,
                "format_name": item["format_name"],
                "duration": item["duration"],
                "bit_rate": item["bit_rate"],
                "codec": item["codec"],
                "resolution": item["resolution"],
                "fps": item["fps"],
                "validation_checks": item["validation_checks"],
            }
            for item in data["evidence_analysis"]
        ],
        "timeline_events": [
            {
                "id": te.id,
                "evidence_id": te.evidence_id,
                "raw_timestamp": te.raw_timestamp,
                "normalized_utc": to_iso8601(te.normalized_timestamp_utc) if te.normalized_timestamp_utc else None,
                "offset_seconds": te.offset_seconds,
                "event_type": te.event_type,
                "description": te.description,
                "analyst_status": te.analyst_status,
            }
            for te in data["timeline_events_raw"]
        ],
        "ai_detections": [
            {
                "id": det.id,
                "segment_id": det.segment_id,
                "frame_number": det.frame_number,
                "frame_timestamp": det.frame_timestamp,
                "class_name": det.class_name,
                "confidence": det.confidence,
                "bounding_box": json.loads(det.bbox_json) if det.bbox_json else None,
                "model_name": det.model_name,
                "reviewer_id": det.reviewer_id,
                "reviewer_status": det.reviewer_status,
                "reviewer_notes": getattr(det, "reviewer_notes", None),
            }
            for det in data["ai_detections"]
        ],
        "legal_compliance": {
            "act": (
                "Indian Evidence Act, 1872 Section 65B / "
                "Bharatiya Sakshya Adhiniyam, 2023 Section 63"
            ),
            "certified_by": case.created_by,
            "tool_name": "ForensIQ Vault",
            "tool_version": TOOL_VERSION,
            "certified_at_utc": timestamp_str,
            "disclaimer": (
                "AI outputs are advisory triage aids. Human review is mandatory "
                "before evidence admission. Biometric facial recognition is strictly prohibited."
            ),
        },
    }
    return json.dumps(dossier, indent=2, ensure_ascii=False)


def _render_pdf_report(rendered_html: str, target_file: Path) -> None:
    """Render HTML string to PDF using native PySide6 QTextDocument and QPdfWriter."""
    from PySide6.QtGui import QGuiApplication, QPageLayout, QPageSize, QTextDocument, QPdfWriter

    # Ensure application instance exists
    app = QGuiApplication.instance()
    if not app:
        app = QGuiApplication(sys.argv if hasattr(sys, "argv") and sys.argv else ["forensiq"])

    doc = QTextDocument()
    doc.setHtml(rendered_html)

    writer = QPdfWriter(str(target_file))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    doc.print_(writer)


def generate_forensic_report(
    session: Session,
    case_id: str,
    report_format: str = "HTML",
    output_path: Optional[Path | str] = None,
    actor_id: str = "Investigator",
) -> tuple[Report, Path]:
    """
    Generate a court-admissible forensic report and register it in the custody ledger.

    Supported formats: "HTML", "JSON", "PDF"

    Workflow:
      1. Gather case details, exhibits, metadata, sanity runs, timeline, AI findings, and custody events.
      2. Render requested format (HTML via Jinja2, JSON dossier, or PDF via QTextDocument).
      3. Compute SHA-256 and MD5 of the generated report file.
      4. Create an atomic `.manifest.json` file for the report and compute its SHA-256.
      5. Insert a `Report` record in the database.
      6. Append a `CustodyAction.REPORT_GENERATED` event into the immutable chain of custody ledger.
      7. Commit session and return `(report, target_file)`.
    """
    format_upper = report_format.strip().upper()
    if format_upper not in ("HTML", "JSON", "PDF"):
        raise ValueError(
            f"Unsupported report format: '{report_format}'. Supported formats are: HTML, JSON, PDF."
        )

    data = _collect_report_data(session, case_id, actor_id=actor_id)
    case = data["case"]
    now_ts = now_utc()
    timestamp_str = to_iso8601(now_ts)

    # Determine destination path
    if output_path is None:
        reports_dir = _cfg.VAULT_ROOT / case_id / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        safe_case = "".join(c for c in case.case_number if c.isalnum() or c in ("-", "_"))
        slug_ts = now_ts.strftime("%Y%m%d_%H%M%S")
        target_file = reports_dir / f"forensic_report_{safe_case}_{slug_ts}.{format_upper.lower()}"
    else:
        target_file = Path(output_path).resolve()
        target_file.parent.mkdir(parents=True, exist_ok=True)

    # Render content
    if format_upper == "HTML":
        html_content = _render_html_report(data, timestamp_str)
        target_file.write_text(html_content, encoding="utf-8")
    elif format_upper == "JSON":
        json_content = _render_json_dossier(data, timestamp_str, actor_id)
        target_file.write_text(json_content, encoding="utf-8")
    elif format_upper == "PDF":
        html_content = _render_html_report(data, timestamp_str)
        _render_pdf_report(html_content, target_file)

    # Compute report file hash
    report_hash_res = hash_file(target_file)
    report_sha256 = report_hash_res.sha256

    # Generate companion manifest
    manifest_file = target_file.with_name(f"{target_file.name}.manifest.json")
    manifest_data = {
        "report_file": target_file.name,
        "sha256": report_sha256,
        "md5": report_hash_res.md5,
        "file_size_bytes": target_file.stat().st_size,
        "generated_at_utc": timestamp_str,
        "tool_version": TOOL_VERSION,
        "case_id": case.id,
        "case_number": case.case_number,
        "report_type": format_upper,
        "generated_by": actor_id,
    }
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    manifest_hash_res = hash_file(manifest_file)
    manifest_sha256 = manifest_hash_res.sha256

    # Determine relative paths
    try:
        rel_path = str(target_file.relative_to(_cfg.VAULT_ROOT))
    except ValueError:
        rel_path = str(target_file)

    try:
        manifest_rel_path = str(manifest_file.relative_to(_cfg.VAULT_ROOT))
    except ValueError:
        manifest_rel_path = str(manifest_file)

    # Persist Report record
    report = Report(
        case_id=case.id,
        report_type=format_upper,
        relative_path=rel_path,
        sha256=report_sha256,
        manifest_relative_path=manifest_rel_path,
        manifest_sha256=manifest_sha256,
        generator_version=TOOL_VERSION,
        generated_by=actor_id,
        generated_at_utc=now_ts,
    )
    session.add(report)
    session.flush()

    # Append Custody Event
    record_event(
        session=session,
        case_id=case.id,
        action=CustodyAction.REPORT_GENERATED,
        actor_id=actor_id,
        output_sha256=report_sha256,
        reason=f"Generated court-admissible forensic dossier ({format_upper})",
        details={
            "report_id": report.id,
            "report_type": format_upper,
            "filename": target_file.name,
            "sha256": report_sha256,
            "manifest_sha256": manifest_sha256,
        },
    )
    session.commit()

    logger.info(
        "Forensic report generated: case=%s format=%s path=%s sha256=%s",
        case.case_number, format_upper, target_file, report_sha256[:8]
    )

    return report, target_file


def list_reports_for_case(session: Session, case_id: str) -> list[Report]:
    """Retrieve all reports generated for a given case in reverse chronological order."""
    return (
        session.query(Report)
        .filter(Report.case_id == case_id)
        .order_by(Report.generated_at_utc.desc())
        .all()
    )


def get_report_by_id(session: Session, report_id: str) -> Optional[Report]:
    """Fetch a single report by its UUID."""
    return session.query(Report).filter(Report.id == report_id).first()


def verify_report_integrity(session: Session, report_id: str) -> tuple[bool, str]:
    """
    Verify that a previously generated report file has not been altered or deleted on disk.

    Returns:
        (is_valid: bool, status_message: str)
    """
    report = get_report_by_id(session, report_id)
    if not report:
        return False, f"Report record '{report_id}' not found."

    # Resolve disk path
    path = Path(report.relative_path)
    if not path.is_absolute():
        path = _cfg.VAULT_ROOT / path

    if not path.exists():
        return False, f"Report file missing on disk: {path}"

    computed_hash = hash_file(path).sha256
    if computed_hash == report.sha256:
        return True, "Cryptographic hash matches. Report integrity intact."
    else:
        return (
            False,
            f"Integrity violation: stored SHA-256 {report.sha256[:8]}… != computed {computed_hash[:8]}…",
        )
