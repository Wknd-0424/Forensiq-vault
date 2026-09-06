"""
tests/test_evidence.py
-----------------------
Integration tests for the full evidence import workflow.

Tests run import_evidence() against an in-memory SQLite database and a
tmp_path vault root — no real VAULT_ROOT or forensiq.db is affected.

Phase 2: Fully implemented.
"""

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from forensiq.database import Base, UTCDateTime, init_db
from forensiq.models.case import Case
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.custody import CustodyEvent
from forensiq.constants import CustodyAction, EvidenceStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to a fresh in-memory SQLite for each test."""
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    # Reset module-level singletons
    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


@pytest.fixture(autouse=True)
def isolate_vault(tmp_path, monkeypatch):
    """Redirect all vault writes to tmp_path."""
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
    yield vault


@pytest.fixture
def mp4_file(tmp_path) -> Path:
    """A valid synthetic .mp4 file (content is not a real video — tests don't parse it)."""
    p = tmp_path / "test_clip.mp4"
    # 100 KB of pseudo-random but deterministic bytes
    p.write_bytes(bytes(range(256)) * 400)
    return p


@pytest.fixture
def created_case(tmp_path) -> str:
    """Create a case in the isolated DB and return its ID."""
    from forensiq.database import session_scope
    from forensiq.services.case_service import create_case
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="EV-TEST-001",
            title="Evidence Import Test Case",
            investigator_name="Test Analyst",
        )
        return case.id


# ---------------------------------------------------------------------------
# TestFileValidation
# ---------------------------------------------------------------------------

class TestFileValidation:

    def test_invalid_extension_raises(self, tmp_path, created_case):
        from forensiq.services.evidence_service import EvidenceImportError, import_evidence
        bad = tmp_path / "document.pdf"
        bad.write_bytes(b"not a video")
        with pytest.raises(EvidenceImportError, match="(?i)extension"):
            import_evidence(
                case_id=created_case,
                source_path=bad,
                investigator="Analyst",
            )

    def test_nonexistent_file_raises(self, tmp_path, created_case):
        from forensiq.services.evidence_service import EvidenceImportError, import_evidence
        with pytest.raises(EvidenceImportError, match="does not exist"):
            import_evidence(
                case_id=created_case,
                source_path=tmp_path / "missing.mp4",
                investigator="Analyst",
            )

    def test_empty_file_raises(self, tmp_path, created_case):
        from forensiq.services.evidence_service import EvidenceImportError, import_evidence
        empty = tmp_path / "empty.mp4"
        empty.write_bytes(b"")
        with pytest.raises(EvidenceImportError):
            import_evidence(
                case_id=created_case,
                source_path=empty,
                investigator="Analyst",
            )

    def test_empty_investigator_raises(self, mp4_file, created_case):
        from forensiq.services.evidence_service import EvidenceImportError, import_evidence
        with pytest.raises(EvidenceImportError, match="[Ii]nvestigator"):
            import_evidence(
                case_id=created_case,
                source_path=mp4_file,
                investigator="   ",  # whitespace only
            )


# ---------------------------------------------------------------------------
# TestImportEvidence — full happy path
# ---------------------------------------------------------------------------

class TestImportEvidence:

    @pytest.fixture
    def import_result(self, mp4_file, created_case):
        from forensiq.services.evidence_service import import_evidence
        return import_evidence(
            case_id=created_case,
            source_path=mp4_file,
            investigator="Forensic Analyst",
            description="Test import",
        )

    def test_returns_import_result(self, import_result):
        from forensiq.services.evidence_service import ImportResult
        assert isinstance(import_result, ImportResult)

    def test_evidence_id_is_uuid(self, import_result):
        import uuid
        uuid.UUID(import_result.evidence_id)  # raises if not a valid UUID

    def test_evidence_number_auto_generated(self, import_result):
        assert import_result.evidence_number.startswith("EVD-")

    def test_sha256_is_64_chars(self, import_result):
        assert len(import_result.original_sha256) == 64

    def test_md5_is_32_chars(self, import_result):
        assert len(import_result.original_md5) == 32

    def test_file_size_correct(self, import_result, mp4_file):
        assert import_result.file_size_bytes == mp4_file.stat().st_size

    def test_working_copy_exists_on_disk(self, import_result):
        assert import_result.working_copy_path.exists()

    def test_working_copy_hash_matches_original(self, import_result, mp4_file):
        from forensiq.utils.hashing import hash_file
        wc_hash = hash_file(import_result.working_copy_path)
        assert wc_hash.sha256 == import_result.original_sha256

    def test_manifest_sha256_nonempty(self, import_result):
        assert len(import_result.manifest_sha256) == 64

    def test_manifest_file_exists(self, import_result):
        manifest = import_result.vault_paths.manifest_path
        assert manifest.exists()

    def test_evidence_item_persisted_in_db(self, import_result):
        from forensiq.services.evidence_service import get_evidence_by_id
        ev = get_evidence_by_id(import_result.evidence_id)
        assert ev is not None
        assert ev.id == import_result.evidence_id

    def test_evidence_status_is_working_copy_ready(self, import_result):
        from forensiq.services.evidence_service import get_evidence_by_id
        ev = get_evidence_by_id(import_result.evidence_id)
        assert ev.status == EvidenceStatus.WORKING_COPY_READY.value

    def test_evidence_sha256_stored(self, import_result):
        from forensiq.services.evidence_service import get_evidence_by_id
        ev = get_evidence_by_id(import_result.evidence_id)
        assert ev.original_sha256 == import_result.original_sha256

    def test_working_copy_record_in_db(self, import_result):
        from forensiq.database import get_session
        session = get_session()
        try:
            wc = session.query(WorkingCopy).filter_by(
                evidence_id=import_result.evidence_id
            ).first()
            assert wc is not None
            assert wc.sha256 == import_result.original_sha256
        finally:
            session.close()


# ---------------------------------------------------------------------------
# TestCustodyEventsAfterImport
# ---------------------------------------------------------------------------

class TestCustodyEventsAfterImport:

    @pytest.fixture
    def import_result(self, mp4_file, created_case):
        from forensiq.services.evidence_service import import_evidence
        return import_evidence(
            case_id=created_case,
            source_path=mp4_file,
            investigator="Chain Analyst",
        )

    def _get_events(self, evidence_id: str) -> list[CustodyEvent]:
        from forensiq.database import get_session
        session = get_session()
        try:
            return (
                session.query(CustodyEvent)
                .filter_by(evidence_id=evidence_id)
                .order_by(CustodyEvent.action_timestamp_utc)
                .all()
            )
        finally:
            session.close()

    def test_at_least_6_custody_events_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        assert len(events) >= 6

    def test_evidence_imported_event_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        actions = [e.action for e in events]
        assert CustodyAction.EVIDENCE_IMPORTED.value in actions

    def test_hash_calculated_event_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        actions = [e.action for e in events]
        assert CustodyAction.HASH_CALCULATED.value in actions

    def test_original_preserved_event_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        actions = [e.action for e in events]
        assert CustodyAction.ORIGINAL_PRESERVED.value in actions

    def test_working_copy_created_event_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        actions = [e.action for e in events]
        assert CustodyAction.WORKING_COPY_CREATED.value in actions

    def test_working_copy_verified_event_recorded(self, import_result):
        events = self._get_events(import_result.evidence_id)
        actions = [e.action for e in events]
        assert CustodyAction.WORKING_COPY_VERIFIED.value in actions

    def test_all_events_linked_to_correct_evidence_id(self, import_result):
        events = self._get_events(import_result.evidence_id)
        for ev in events:
            assert ev.evidence_id == import_result.evidence_id

    def test_all_events_have_non_empty_hash(self, import_result):
        events = self._get_events(import_result.evidence_id)
        for ev in events:
            assert ev.event_hash and len(ev.event_hash) == 64

    def test_custody_chain_is_valid(self, import_result):
        from forensiq.services.custody_service import verify_chain
        from forensiq.constants import ChainVerificationResult
        from forensiq.database import get_session
        from forensiq.models.evidence import EvidenceItem
        session = get_session()
        try:
            ev = session.query(EvidenceItem).filter_by(
                id=import_result.evidence_id
            ).first()
            result, errors = verify_chain(session, ev.case_id)
        finally:
            session.close()
        assert result == ChainVerificationResult.VALID, errors


# ---------------------------------------------------------------------------
# TestDuplicateEvidenceNumber
# ---------------------------------------------------------------------------

class TestDuplicateEvidenceNumber:

    def test_duplicate_evidence_number_raises(self, mp4_file, created_case, tmp_path):
        from forensiq.services.evidence_service import EvidenceImportError, import_evidence
        # First import
        import_evidence(
            case_id=created_case,
            source_path=mp4_file,
            investigator="Analyst",
            evidence_number="EVD-DUPE",
        )
        # Second file
        p2 = tmp_path / "clip2.mp4"
        p2.write_bytes(b"different content here " * 500)
        # Second import with same evidence number must fail
        with pytest.raises(EvidenceImportError, match="already exists"):
            import_evidence(
                case_id=created_case,
                source_path=p2,
                investigator="Analyst",
                evidence_number="EVD-DUPE",
            )


# ---------------------------------------------------------------------------
# TestListEvidence
# ---------------------------------------------------------------------------

class TestListEvidence:

    def test_list_evidence_empty_for_new_case(self, created_case):
        from forensiq.services.evidence_service import list_evidence
        items = list_evidence(created_case)
        assert items == []

    def test_list_evidence_after_import(self, mp4_file, created_case):
        from forensiq.services.evidence_service import import_evidence, list_evidence
        import_evidence(
            case_id=created_case,
            source_path=mp4_file,
            investigator="Analyst",
        )
        items = list_evidence(created_case)
        assert len(items) == 1

    def test_get_evidence_by_id_returns_correct_item(self, mp4_file, created_case):
        from forensiq.services.evidence_service import get_evidence_by_id, import_evidence
        result = import_evidence(
            case_id=created_case,
            source_path=mp4_file,
            investigator="Analyst",
        )
        ev = get_evidence_by_id(result.evidence_id)
        assert ev is not None
        assert ev.id == result.evidence_id

    def test_get_evidence_by_unknown_id_returns_none(self):
        from forensiq.services.evidence_service import get_evidence_by_id
        assert get_evidence_by_id("00000000-0000-0000-0000-000000000000") is None
