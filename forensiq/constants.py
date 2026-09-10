"""
forensiq/constants.py
---------------------
All enumerations and fixed string constants used across the application.
Using str-based enums allows direct storage in SQLite without conversion.
"""

from enum import Enum


class CaseStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class UserRole(str, Enum):
    ADMIN = "Admin"
    INVESTIGATOR = "Investigator"
    REVIEWER = "Reviewer"
    VIEWER = "Viewer"


class CustodyAction(str, Enum):
    """Every action recorded in the hash-linked chain-of-custody ledger."""
    CASE_CREATED = "CASE_CREATED"
    EVIDENCE_IMPORTED = "EVIDENCE_IMPORTED"
    HASH_CALCULATED = "HASH_CALCULATED"
    ORIGINAL_PRESERVED = "ORIGINAL_PRESERVED"
    READ_ONLY_SET = "READ_ONLY_SET"
    READ_ONLY_FAILED = "READ_ONLY_FAILED"
    IMAGE_CREATED = "IMAGE_CREATED"
    IMAGE_VERIFIED = "IMAGE_VERIFIED"
    WORKING_COPY_CREATED = "WORKING_COPY_CREATED"
    WORKING_COPY_VERIFIED = "WORKING_COPY_VERIFIED"
    WORKING_COPY_VERIFICATION_FAILED = "WORKING_COPY_VERIFICATION_FAILED"
    METADATA_EXTRACTED = "METADATA_EXTRACTED"
    TIMESTAMP_NORMALIZATION_APPLIED = "TIMESTAMP_NORMALIZATION_APPLIED"
    AI_ANALYSIS_STARTED = "AI_ANALYSIS_STARTED"
    AI_ANALYSIS_COMPLETED = "AI_ANALYSIS_COMPLETED"
    DETECTION_REVIEWED = "DETECTION_REVIEWED"
    REPORT_GENERATED = "REPORT_GENERATED"
    MANIFEST_GENERATED = "MANIFEST_GENERATED"
    VALIDATION_RUN = "VALIDATION_RUN"
    DERIVATIVE_CREATED = "DERIVATIVE_CREATED"
    RECOVERY_ATTEMPTED = "RECOVERY_ATTEMPTED"
    CUSTODY_TRANSFERRED = "CUSTODY_TRANSFERRED"
    ANALYST_NOTE = "ANALYST_NOTE"
    DISPOSITION_SET = "DISPOSITION_SET"


class EvidenceStatus(str, Enum):
    IMPORTED = "IMPORTED"
    HASHED = "HASHED"
    PRESERVED = "PRESERVED"
    WORKING_COPY_READY = "WORKING_COPY_READY"
    ANALYZED = "ANALYZED"
    FAILED = "FAILED"


class WorkingCopyStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"


class ChainVerificationResult(str, Enum):
    VALID = "VALID"
    INVALID_EVENT_HASH = "INVALID_EVENT_HASH"
    INVALID_PREVIOUS_LINK = "INVALID_PREVIOUS_LINK"
    MISSING_EVENT = "MISSING_EVENT"
    EMPTY_CHAIN = "EMPTY_CHAIN"


class AdapterStatus(str, Enum):
    TESTED = "TESTED"
    EXPERIMENTAL = "EXPERIMENTAL"
    PLACEHOLDER = "PLACEHOLDER"
    PLANNED = "PLANNED"
    SAFE_FAILURE = "SAFE_FAILURE"


class ParseStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class ReviewerStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class RecoveryStatus(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    UNSUPPORTED = "UNSUPPORTED"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNRECOVERABLE = "UNRECOVERABLE"
    FAILED = "FAILED"


class EvidenceType(str, Enum):
    VIDEO_FILE = "VIDEO_FILE"
    DISK_IMAGE = "DISK_IMAGE"
    EXPORT_PACKAGE = "EXPORT_PACKAGE"
    UNKNOWN = "UNKNOWN"


class NormalizationMethod(str, Enum):
    ANALYST_OFFSET = "ANALYST_OFFSET"
    NTP_REFERENCE = "NTP_REFERENCE"
    REFERENCE_EVENT = "REFERENCE_EVENT"
    MANUFACTURER_DRIFT = "MANUFACTURER_DRIFT"
    NONE = "NONE"


class TimelineEventType(str, Enum):
    METADATA = "METADATA"
    AI_PRELIMINARY = "AI_PRELIMINARY"
    ANALYST_BOOKMARK = "ANALYST_BOOKMARK"
    RECOVERY_RESULT = "RECOVERY_RESULT"
    MANUAL_ENTRY = "MANUAL_ENTRY"


class AnalystStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


# ---------------------------------------------------------------------------
# UI strings (not internationalised in MVP)
# ---------------------------------------------------------------------------

MANDATORY_DISCLAIMER: str = (
    "AI outputs are triage aids. False positives and false negatives are "
    "possible. Human review is required. A matching hash verifies byte-level "
    "equality of compared files; it does not independently establish "
    "original-world authenticity, completeness, correct timestamps, or legal "
    "admissibility."
)

CUSTODY_TAMPER_LIMITATION: str = (
    "This custody ledger is tamper-evident within the application. Stronger "
    "protection requires access controls, protected backups, independently "
    "stored or signed checkpoints, and organisation-level forensic procedures."
)

RECOVERY_WARNING: str = (
    "Overwritten, encrypted, physically damaged, incomplete or heavily "
    "fragmented footage may be unrecoverable. Recovery outcomes must be "
    "validated against controlled ground truth where available."
)

MD5_NOTE: str = (
    "MD5 is included for legacy compatibility. "
    "SHA-256 is the primary integrity algorithm used by this prototype."
)
