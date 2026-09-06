"""
tests/test_cases.py
--------------------
Unit tests for the Case model, case_service and custody_service.

Phase 1 coverage:
  - Case creation with valid data.
  - Case number uniqueness enforcement.
  - Empty case number is rejected.
  - Empty title is rejected.
  - Empty investigator name is rejected.
  - Case is persisted to the database.
  - list_cases() returns all created cases.
  - get_case() returns correct case by UUID.
  - get_case() returns None for unknown UUID.
  - CASE_CREATED custody event is recorded on case creation.
  - CASE_CREATED event_hash is non-empty.
  - Chain verification on a fresh case returns VALID.
  - Case stats reflect created cases.

All tests use an in-memory SQLite database — no test data touches the
real forensiq.db or the vault directory.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from forensiq.database import Base
from forensiq.models import _import_all_models
from forensiq.constants import CaseStatus, ChainVerificationResult, CustodyAction
from forensiq.models.case import Case
from forensiq.models.custody import CustodyEvent
from forensiq.services.case_service import (
    CaseValidationError,
    create_case,
    get_case,
    get_case_by_number,
    get_case_stats,
    list_cases,
)
from forensiq.services.custody_service import verify_chain


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def db_session():
    """
    Provide a fresh in-memory SQLite session for each test function.
    Schema is created from the ORM models and dropped after the test.
    """
    _import_all_models()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_case(session, number="FIR-2026-001", title="Test Case",
               investigator="Det. Sharma"):
    """Create and commit a test case."""
    case = create_case(
        session=session,
        case_number=number,
        title=title,
        investigator_name=investigator,
        description="Test case for unit testing.",
        authority_reference="AUTH-001",
    )
    session.commit()
    return case


# ---------------------------------------------------------------------------
# Case creation — happy path
# ---------------------------------------------------------------------------

class TestCaseCreation:

    def test_create_case_returns_case_object(self, db_session):
        case = _make_case(db_session)
        assert isinstance(case, Case)

    def test_created_case_has_uuid(self, db_session):
        case = _make_case(db_session)
        assert len(case.id) == 36
        assert case.id.count("-") == 4

    def test_created_case_has_correct_number(self, db_session):
        case = _make_case(db_session, number="FIR-2026-XYZ")
        assert case.case_number == "FIR-2026-XYZ"

    def test_created_case_has_correct_title(self, db_session):
        case = _make_case(db_session, title="Bank Robbery Surveillance")
        assert case.title == "Bank Robbery Surveillance"

    def test_created_case_has_correct_investigator(self, db_session):
        case = _make_case(db_session, investigator="Insp. Patel")
        assert case.created_by == "Insp. Patel"

    def test_created_case_status_is_active(self, db_session):
        case = _make_case(db_session)
        assert case.status == CaseStatus.ACTIVE

    def test_created_case_has_utc_timestamps(self, db_session):
        from datetime import timezone
        case = _make_case(db_session)
        assert case.created_at_utc.tzinfo is not None
        assert case.created_at_utc.tzinfo == timezone.utc

    def test_created_case_is_persisted(self, db_session):
        case = _make_case(db_session)
        fetched = db_session.query(Case).filter(Case.id == case.id).first()
        assert fetched is not None
        assert fetched.case_number == case.case_number


# ---------------------------------------------------------------------------
# Case creation — validation errors
# ---------------------------------------------------------------------------

class TestCaseValidation:

    def test_empty_case_number_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "", "Title", "Investigator")

    def test_whitespace_case_number_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "   ", "Title", "Investigator")

    def test_empty_title_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "FIR-001", "", "Investigator")

    def test_whitespace_title_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "FIR-001", "   ", "Investigator")

    def test_empty_investigator_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "FIR-001", "Title", "")

    def test_whitespace_investigator_raises(self, db_session):
        with pytest.raises(CaseValidationError, match="empty"):
            create_case(db_session, "FIR-001", "Title", "   ")

    def test_case_number_too_long_raises(self, db_session):
        long_number = "X" * 101
        with pytest.raises(CaseValidationError, match="100 characters"):
            create_case(db_session, long_number, "Title", "Investigator")

    def test_title_too_long_raises(self, db_session):
        long_title = "T" * 501
        with pytest.raises(CaseValidationError, match="500 characters"):
            create_case(db_session, "FIR-001", long_title, "Investigator")

    def test_duplicate_case_number_raises(self, db_session):
        _make_case(db_session, number="FIR-DUPE-001")
        with pytest.raises(CaseValidationError, match="already exists"):
            create_case(db_session, "FIR-DUPE-001", "Another Title", "Investigator")

    def test_leading_trailing_whitespace_is_stripped(self, db_session):
        case = create_case(
            db_session,
            "  FIR-STRIP-001  ",
            "  Stripped Title  ",
            "  Det. Sharma  ",
        )
        db_session.commit()
        assert case.case_number == "FIR-STRIP-001"
        assert case.title == "Stripped Title"
        assert case.created_by == "Det. Sharma"


# ---------------------------------------------------------------------------
# Case retrieval
# ---------------------------------------------------------------------------

class TestCaseRetrieval:

    def test_list_cases_returns_created_cases(self, db_session):
        _make_case(db_session, number="LIST-001")
        _make_case(db_session, number="LIST-002")
        cases = list_cases(db_session)
        numbers = {c.case_number for c in cases}
        assert "LIST-001" in numbers
        assert "LIST-002" in numbers

    def test_get_case_by_id(self, db_session):
        case = _make_case(db_session)
        fetched = get_case(db_session, case.id)
        assert fetched is not None
        assert fetched.id == case.id

    def test_get_case_unknown_id_returns_none(self, db_session):
        result = get_case(db_session, "00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_get_case_by_number(self, db_session):
        _make_case(db_session, number="BY-NUM-001")
        fetched = get_case_by_number(db_session, "BY-NUM-001")
        assert fetched is not None
        assert fetched.case_number == "BY-NUM-001"

    def test_get_case_by_number_not_found_returns_none(self, db_session):
        result = get_case_by_number(db_session, "DOES-NOT-EXIST")
        assert result is None


# ---------------------------------------------------------------------------
# Case stats
# ---------------------------------------------------------------------------

class TestCaseStats:

    def test_stats_total_count(self, db_session):
        _make_case(db_session, number="STAT-001")
        _make_case(db_session, number="STAT-002")
        stats = get_case_stats(db_session)
        assert stats["total"] >= 2

    def test_stats_active_count(self, db_session):
        _make_case(db_session, number="ACTIVE-001")
        stats = get_case_stats(db_session)
        assert stats["active"] >= 1


# ---------------------------------------------------------------------------
# Custody chain
# ---------------------------------------------------------------------------

class TestCaseCustodyChain:

    def test_case_created_event_is_recorded(self, db_session):
        case = _make_case(db_session)
        events = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .all()
        )
        assert len(events) == 1
        assert events[0].action == CustodyAction.CASE_CREATED

    def test_case_created_event_has_non_empty_hash(self, db_session):
        case = _make_case(db_session)
        event = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .first()
        )
        assert event is not None
        assert len(event.event_hash) == 64  # SHA-256 hex = 64 chars

    def test_case_created_event_previous_hash_is_none(self, db_session):
        """First event in a chain has no predecessor."""
        case = _make_case(db_session)
        event = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .first()
        )
        assert event.previous_event_hash is None

    def test_chain_verification_valid_after_creation(self, db_session):
        case = _make_case(db_session)
        result, errors = verify_chain(db_session, case.id)
        assert result == ChainVerificationResult.VALID
        assert errors == []

    def test_chain_verification_empty_for_unknown_case(self, db_session):
        result, errors = verify_chain(db_session, "00000000-0000-0000-0000-000000000000")
        assert result == ChainVerificationResult.EMPTY_CHAIN

    def test_tampered_event_hash_detected(self, db_session):
        """Mutating stored event_hash must be detected by verify_chain."""
        case = _make_case(db_session)
        event = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .first()
        )
        # Tamper with the stored hash
        event.event_hash = "a" * 64
        db_session.commit()

        result, errors = verify_chain(db_session, case.id)
        assert result == ChainVerificationResult.INVALID_EVENT_HASH
        assert len(errors) > 0

    def test_tampered_previous_hash_detected(self, db_session):
        """Mutating previous_event_hash on the second event must be detected."""
        from forensiq.services.custody_service import record_event
        case = _make_case(db_session)

        # Add a second event
        record_event(
            session=db_session,
            case_id=case.id,
            action=CustodyAction.EVIDENCE_IMPORTED,
            actor_id="Test",
            reason="Second event for chain test",
        )
        db_session.commit()

        # Tamper: change previous_event_hash on the second event
        events = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .order_by(CustodyEvent.action_timestamp_utc.asc())
            .all()
        )
        assert len(events) == 2
        second = events[1]
        second.previous_event_hash = "b" * 64
        db_session.commit()

        result, errors = verify_chain(db_session, case.id)
        # The second event's hash will now fail (fields include tampered prev hash)
        assert result in (
            ChainVerificationResult.INVALID_EVENT_HASH,
            ChainVerificationResult.INVALID_PREVIOUS_LINK,
        )
        assert len(errors) > 0

    def test_event_actor_is_investigator_name(self, db_session):
        case = _make_case(db_session, investigator="Insp. Kumar")
        event = (
            db_session.query(CustodyEvent)
            .filter(CustodyEvent.case_id == case.id)
            .first()
        )
        assert event.actor_id == "Insp. Kumar"
