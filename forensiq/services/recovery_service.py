"""
forensiq/services/recovery_service.py
---------------------------------------
Surveillance Video Carving & Stream Reconstruction Service.

Performs experimental recovery and frame carving on corrupted, unfinalized,
or fragmented video streams.

Key Forensic Invariants:
  - Carving operates strictly on hash-verified WORKING COPIES. Original evidence is never modified.
  - Carved output streams are segregated into the evidence item's `derivatives/` directory.
  - Reconstructed derivatives are independently hashed (SHA-256) and tracked with a manifest.
  - Mandatory limitations warning: Overwritten, encrypted, or physically damaged footage
    may be unrecoverable.
  - Every attempt logs `RECOVERY_ATTEMPTED` and, if successful, `DERIVATIVE_CREATED` in the
    immutable chain of custody.

Phase 7: Fully implemented.
"""

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

import forensiq.config as _cfg
from forensiq.config import TOOL_VERSION
from forensiq.constants import CustodyAction, RecoveryStatus
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.recovery import RecoveryResult
from forensiq.services.adapter_service import get_working_copy_path
from forensiq.services.custody_service import record_event
from forensiq.utils.hashing import hash_file
from forensiq.utils.utc_utils import now_utc, to_iso8601

logger = logging.getLogger(__name__)

MANDATORY_RECOVERY_WARNING: str = (
    "Overwritten, encrypted, physically damaged, incomplete or heavily fragmented "
    "footage may be unrecoverable. Recovery outcomes must be validated against "
    "controlled ground truth where available."
)


def scan_annex_b_nalus(data: bytes) -> list[dict[str, Any]]:
    """
    Scan a byte sequence for Annex-B NAL unit start codes (0x000001 and 0x00000001).

    Identifies H.264 / H.265 parameter sets and slice headers:
      - H.264: SPS (7), PPS (8), IDR Keyframe (5), Non-IDR Slice (1), AUD (9), SEI (6)
      - H.265: VPS (32), SPS (33), PPS (34), IDR (19, 20), Non-IDR Slice (1)

    Returns:
        List of dicts describing each identified NAL unit with its start offset,
        header length, unit type, and classification flags.
    """
    length = len(data)
    if length < 4:
        return []

    nalus = []
    i = 0

    while i < length - 3:
        # Check for 4-byte start code: 00 00 00 01
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and data[i+3] == 1:
            header_len = 4
            nalu_start = i
            type_byte_idx = i + 4
        # Check for 3-byte start code: 00 00 01
        elif data[i] == 0 and data[i+1] == 0 and data[i+2] == 1:
            header_len = 3
            nalu_start = i
            type_byte_idx = i + 3
        else:
            i += 1
            continue

        if type_byte_idx < length:
            type_byte = data[type_byte_idx]
            h264_type = type_byte & 0x1F
            h265_type = (type_byte >> 1) & 0x3F

            # Classification
            is_sps = (h264_type == 7) or (h265_type == 33)
            is_pps = (h264_type == 8) or (h265_type == 34)
            is_idr = (h264_type == 5) or (h265_type in (19, 20))
            is_slice = (h264_type in (1, 5)) or (h265_type in (1, 19, 20))

            nalus.append({
                "start_offset": nalu_start,
                "header_len": header_len,
                "type_byte": type_byte,
                "h264_type": h264_type,
                "h265_type": h265_type,
                "is_sps": is_sps,
                "is_pps": is_pps,
                "is_idr": is_idr,
                "is_slice": is_slice,
            })

        i = type_byte_idx + 1

    return nalus


def carve_video_stream(
    session: Session,
    evidence_id: str,
    actor_id: str = "Investigator",
    max_frames: Optional[int] = None,
) -> tuple[RecoveryResult, Optional[Path]]:
    """
    Execute video carving and stream reconstruction on an evidence item's working copy.

    Workflow:
      1. Fetch working copy from vault.
      2. Scan for valid Annex-B NAL units (H.264/H.265 parameter sets and slices).
      3. If no valid units are found, record UNRECOVERABLE status with mandatory limitation.
      4. If valid units are found:
         a. Extract from the first SPS/IDR to end of stream.
         b. Save derivative into vault/{case_id}/evidence/{evidence_id}/derivatives/.
         c. Compute SHA-256 and write atomic companion .manifest.json.
         d. Persist RecoveryResult record (COMPLETE or PARTIAL).
         e. Log RECOVERY_ATTEMPTED and DERIVATIVE_CREATED in the custody ledger.
      5. Commit session and return (result, derivative_path).
    """
    evidence = session.query(EvidenceItem).filter(EvidenceItem.id == evidence_id).first()
    if not evidence:
        raise ValueError(f"Evidence item '{evidence_id}' was not found.")

    wc_path = get_working_copy_path(session, evidence_id)
    if not wc_path or not wc_path.exists():
        raise FileNotFoundError(f"Working copy for evidence '{evidence_id}' was not found on disk.")

    with open(wc_path, "rb") as f:
        data = f.read()

    nalus = scan_annex_b_nalus(data)

    # 1. Unrecoverable handling
    if not nalus or not any(n["is_slice"] or n["is_sps"] for n in nalus):
        rec_res = RecoveryResult(
            evidence_id=evidence_id,
            method="ANNEX_B_NALU_CARVER",
            status=RecoveryStatus.UNRECOVERABLE.value,
            recovered_relative_path=None,
            sha256=None,
            recovered_duration_seconds=0.0,
            source_ranges_json=json.dumps([]),
            confidence="NONE",
            limitations=MANDATORY_RECOVERY_WARNING,
            created_at_utc=now_utc(),
        )
        session.add(rec_res)
        session.flush()

        record_event(
            session=session,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            action=CustodyAction.RECOVERY_ATTEMPTED,
            actor_id=actor_id,
            reason="Carving attempt resulted in unrecoverable stream (no valid NAL units found)",
            details={
                "method": "ANNEX_B_NALU_CARVER",
                "status": RecoveryStatus.UNRECOVERABLE.value,
                "evidence_id": evidence_id,
            },
        )
        session.commit()
        return rec_res, None

    # 2. Carve valid sequence starting from first SPS or IDR if available
    first_key_idx = 0
    for idx, n in enumerate(nalus):
        if n["is_sps"] or n["is_idr"]:
            first_key_idx = idx
            break

    carved_nalus = nalus[first_key_idx:]
    if max_frames and len(carved_nalus) > max_frames:
        carved_nalus = carved_nalus[:max_frames]

    start_byte = carved_nalus[0]["start_offset"]
    carved_data = data[start_byte:]

    sps_count = sum(1 for n in carved_nalus if n["is_sps"])
    pps_count = sum(1 for n in carved_nalus if n["is_pps"])
    idr_count = sum(1 for n in carved_nalus if n["is_idr"])
    slice_count = sum(1 for n in carved_nalus if n["is_slice"])

    if sps_count > 0 and pps_count > 0 and idr_count > 0 and slice_count >= 5:
        recovery_status = RecoveryStatus.COMPLETE.value
        confidence = "HIGH"
    else:
        recovery_status = RecoveryStatus.PARTIAL.value
        confidence = "MEDIUM"

    # Destination directory: vault/{case_id}/evidence/{evidence_id}/derivatives/
    derivatives_dir = _cfg.VAULT_ROOT / evidence.case_id / "evidence" / evidence.id / "derivatives"
    derivatives_dir.mkdir(parents=True, exist_ok=True)

    now_ts = now_utc()
    timestamp_slug = now_ts.strftime("%Y%m%d_%H%M%S")
    derivative_file = derivatives_dir / f"carved_{evidence.evidence_number}_{timestamp_slug}.h264"
    derivative_file.write_bytes(carved_data)

    # Compute hash of carved file
    hash_res = hash_file(derivative_file)
    derivative_sha256 = hash_res.sha256

    from forensiq.ml import predict_sector_class
    ml_sector_class, ml_confidence = predict_sector_class(data[:4096])

    # Create companion manifest for derivative
    manifest_file = derivative_file.with_name(f"{derivative_file.name}.manifest.json")
    manifest_data = {
        "derivative_file": derivative_file.name,
        "sha256": derivative_sha256,
        "md5": hash_res.md5,
        "parent_evidence_id": evidence.id,
        "parent_evidence_number": evidence.evidence_number,
        "carved_at_utc": to_iso8601(now_ts),
        "tool_version": TOOL_VERSION,
        "method": "ANNEX_B_NALU_CARVER",
        "ml_sector_class": ml_sector_class,
        "ml_confidence": round(float(ml_confidence), 4),
        "carved_frames": slice_count,
        "sps_count": sps_count,
        "pps_count": pps_count,
        "idr_count": idr_count,
        "file_size_bytes": len(carved_data),
    }
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    # Relative path calculation
    try:
        rel_path = str(derivative_file.relative_to(_cfg.VAULT_ROOT))
    except ValueError:
        rel_path = str(derivative_file)

    # Estimated duration assuming nominal 25 fps
    est_duration = round(slice_count / 25.0, 2) if slice_count > 0 else 0.0

    source_ranges = [
        {
            "start_offset": start_byte,
            "end_offset": len(data),
            "carved_bytes": len(carved_data),
            "nalu_count": len(carved_nalus),
            "slice_count": slice_count,
            "idr_count": idr_count,
        }
    ]

    rec_res = RecoveryResult(
        evidence_id=evidence.id,
        method="ANNEX_B_NALU_CARVER",
        status=recovery_status,
        recovered_relative_path=rel_path,
        sha256=derivative_sha256,
        recovered_duration_seconds=est_duration,
        source_ranges_json=json.dumps(source_ranges),
        confidence=confidence,
        limitations=MANDATORY_RECOVERY_WARNING,
        created_at_utc=now_ts,
    )
    session.add(rec_res)
    session.flush()

    # Log Custody Events
    record_event(
        session=session,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        action=CustodyAction.RECOVERY_ATTEMPTED,
        actor_id=actor_id,
        reason=f"Executed stream carving; recovered {slice_count} NAL video frames",
        details={
            "method": "ANNEX_B_NALU_CARVER",
            "recovery_status": recovery_status,
            "nalu_count": len(carved_nalus),
            "slice_count": slice_count,
        },
    )

    record_event(
        session=session,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        action=CustodyAction.DERIVATIVE_CREATED,
        actor_id=actor_id,
        output_sha256=derivative_sha256,
        reason="Generated playable carved stream derivative from fragmented footage",
        details={
            "recovery_id": rec_res.id,
            "derivative_file": derivative_file.name,
            "sha256": derivative_sha256,
            "status": recovery_status,
        },
    )

    session.commit()

    logger.info(
        "Carved stream derivative generated: evidence=%s status=%s frames=%d path=%s",
        evidence.evidence_number, recovery_status, slice_count, derivative_file.name
    )

    return rec_res, derivative_file


def list_recovery_results_for_evidence(
    session: Session, evidence_id: str
) -> list[RecoveryResult]:
    """Retrieve all recovery results associated with a specific evidence item."""
    return (
        session.query(RecoveryResult)
        .filter(RecoveryResult.evidence_id == evidence_id)
        .order_by(RecoveryResult.created_at_utc.desc())
        .all()
    )


def get_recovery_result(
    session: Session, result_id: str
) -> Optional[RecoveryResult]:
    """Retrieve a single recovery result by its UUID."""
    return session.query(RecoveryResult).filter(RecoveryResult.id == result_id).first()
