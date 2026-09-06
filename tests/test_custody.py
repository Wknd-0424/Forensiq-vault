"""
tests/test_custody.py
---------------------
Tests for Phase 3 — Chain of Custody Ledger & Cryptographic Verification:
  - Sequential hash chaining and genesis block properties
  - Cryptographic verification algorithm (SHA-256 link validation)
  - Tamper detection vectors:
      * Altered event payload (INVALID_EVENT_HASH)
      * Altered previous link (INVALID_PREVIOUS_LINK)
      * Direct event_hash modification (INVALID_EVENT_HASH)
      * Deleted intermediate event (INVALID_PREVIOUS_LINK)
  - Manual custody event creation (CUSTODY_TRANSFERRED, ANALYST_NOTE, DISPOSITION_SET)
  - Canonical JSON and CSV ledger exports
  - Chain filtering by case and by evidence

Phase 3: Fully implemented.
"""

import json
from pathlib import Path

import pytest

from forensiq.constants import ChainVerificationResult, CustodyAction
from forensiq.database import init_db, session_scope
from forensiq.models.custody import CustodyEvent
from forensiq.services.case_service import create_case
from forensiq.services.custody_service import (
    export_custody_ledger_csv,
    export_custody_ledger_json,
    get_chain_for_case,
    get_chain_for_evidence,
    record_event,
    record_manual_event,
    verify_case_chain,
    verify_chain,
)


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect all DB access to a fresh SQLite database for each test."""
    db_url = f"sqlite:///{tmp_path / 'test_custody.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


@pytest.fixture
def case_id() -> str:
    """Create a case and return its ID."""
    with session_scope() as session:
        case = create_case(
            session=session,
            case_number="CUST-TEST-001",
            title="Custody Ledger Test Case",
            investigator_name="Agent Smith",
        )
        return case.id


# ─────────────────────────────────────────────────────────────────────────────
# 1. Chain Construction
# ─────────────────────────────────────────────────────────────────────────────

class TestCustodyChainConstruction:

    def test_genesis_event_has_none_previous_hash(self, case_id):
        with session_scope() as session:
            events = get_chain_for_case(session, case_id)
            # Case creation automatically writes CASE_CREATED as the genesis event
            assert len(events) == 1
            genesis = events[0]
            assert genesis.action == CustodyAction.CASE_CREATED.value
            assert genesis.previous_event_hash is None
            assert len(genesis.event_hash) == 64

    def test_subsequent_events_link_correctly(self, case_id):
        with session_scope() as session:
            ev2 = record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                actor_id="Agent Smith",
                reason="Imported physical disk",
            )
            ev3 = record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.HASH_CALCULATED,
                actor_id="Agent Smith",
                output_sha256="a" * 64,
            )

        with session_scope() as session:
            chain = get_chain_for_case(session, case_id)
            assert len(chain) == 3
            assert chain[0].previous_event_hash is None
            assert chain[1].previous_event_hash == chain[0].event_hash
            assert chain[2].previous_event_hash == chain[1].event_hash

    def test_all_event_hashes_are_unique_sha256(self, case_id):
        with session_scope() as session:
            for i in range(5):
                record_event(
                    session=session,
                    case_id=case_id,
                    action=CustodyAction.ANALYST_NOTE,
                    actor_id="Agent Smith",
                    reason=f"Note {i}",
                )

        with session_scope() as session:
            chain = get_chain_for_case(session, case_id)
            hashes = [e.event_hash for e in chain]
            assert len(set(hashes)) == len(chain)
            for h in hashes:
                assert len(h) == 64
                int(h, 16)  # valid hex


# ─────────────────────────────────────────────────────────────────────────────
# 2. Chain Verification & Tamper Detection
# ─────────────────────────────────────────────────────────────────────────────

class TestCustodyChainVerification:

    def test_valid_chain_verifies_successfully(self, case_id):
        with session_scope() as session:
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                actor_id="Analyst 1",
            )
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.WORKING_COPY_VERIFIED,
                actor_id="Analyst 1",
            )

        with session_scope() as session:
            result, errors = verify_chain(session, case_id)
            assert result == ChainVerificationResult.VALID
            assert errors == []

    def test_empty_chain_returns_empty_result(self):
        with session_scope() as session:
            result, errors = verify_chain(session, "nonexistent-case-id")
            assert result == ChainVerificationResult.EMPTY_CHAIN
            assert len(errors) == 1

    def test_tampered_payload_detected(self, case_id):
        with session_scope() as session:
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                actor_id="Legitimate Officer",
            )

        # Tamper with the actor in DB without updating event_hash
        with session_scope() as session:
            ev = session.query(CustodyEvent).filter_by(action=CustodyAction.EVIDENCE_IMPORTED.value).first()
            ev.actor_id = "Malicious Impersonator"

        with session_scope() as session:
            result, errors = verify_chain(session, case_id)
            assert result == ChainVerificationResult.INVALID_EVENT_HASH
            assert len(errors) == 1
            assert "does not match recomputed hash" in errors[0]

    def test_tampered_previous_hash_detected(self, case_id):
        with session_scope() as session:
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                actor_id="Officer 1",
            )
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.HASH_CALCULATED,
                actor_id="Officer 1",
            )

        # Tamper with previous_event_hash of event 3
        with session_scope() as session:
            ev3 = session.query(CustodyEvent).filter_by(action=CustodyAction.HASH_CALCULATED.value).first()
            ev3.previous_event_hash = "0" * 64
            # Recompute event_hash so check 1 passes, but check 2 (linkage) fails
            from forensiq.services.custody_service import _event_to_hashable_dict, _hash_event_fields
            ev3.event_hash = _hash_event_fields(_event_to_hashable_dict(ev3))

        with session_scope() as session:
            result, errors = verify_chain(session, case_id)
            assert result == ChainVerificationResult.INVALID_PREVIOUS_LINK
            assert len(errors) == 1
            assert "does not match prior event hash" in errors[0]

    def test_deleted_intermediate_event_detected(self, case_id):
        with session_scope() as session:
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                actor_id="Officer 1",
            )
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.HASH_CALCULATED,
                actor_id="Officer 1",
            )

        # Delete the middle event (EVIDENCE_IMPORTED)
        with session_scope() as session:
            middle = session.query(CustodyEvent).filter_by(action=CustodyAction.EVIDENCE_IMPORTED.value).first()
            session.delete(middle)

        # Now event 3 points to deleted event 2's hash, but the prior in DB is event 1 (CASE_CREATED)
        with session_scope() as session:
            result, errors = verify_chain(session, case_id)
            assert result == ChainVerificationResult.INVALID_PREVIOUS_LINK

    def test_standalone_verify_case_chain_helper(self, case_id):
        result, errors = verify_case_chain(case_id)
        assert result == ChainVerificationResult.VALID
        assert errors == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. Manual Custody Events
# ─────────────────────────────────────────────────────────────────────────────

class TestManualCustodyEvents:

    def test_record_custody_transferred(self, case_id):
        with session_scope() as session:
            ev = record_manual_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.CUSTODY_TRANSFERRED,
                actor_id="Forensic Detective Miller",
                reason="Transferred evidence drive to central state forensic cyber cell.",
            )
            assert ev.action == CustodyAction.CUSTODY_TRANSFERRED.value
            assert ev.actor_id == "Forensic Detective Miller"

        res, _ = verify_case_chain(case_id)
        assert res == ChainVerificationResult.VALID

    def test_record_analyst_note(self, case_id):
        with session_scope() as session:
            ev = record_manual_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.ANALYST_NOTE,
                actor_id="Analyst Rao",
                reason="Reviewed timestamp offset against NTP server logs.",
            )
            assert ev.action == CustodyAction.ANALYST_NOTE.value

        res, _ = verify_case_chain(case_id)
        assert res == ChainVerificationResult.VALID

    def test_record_disposition_set(self, case_id):
        with session_scope() as session:
            ev = record_manual_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.DISPOSITION_SET,
                actor_id="Supervisor Patel",
                reason="Case retained under court order Rule 65B.",
            )
            assert ev.action == CustodyAction.DISPOSITION_SET.value

        res, _ = verify_case_chain(case_id)
        assert res == ChainVerificationResult.VALID

    def test_empty_actor_raises_value_error(self, case_id):
        with session_scope() as session:
            with pytest.raises(ValueError, match="Actor/Investigator name is required"):
                record_manual_event(
                    session=session,
                    case_id=case_id,
                    action=CustodyAction.CUSTODY_TRANSFERRED,
                    actor_id="   ",
                    reason="Transfer reason",
                )

    def test_invalid_action_raises_value_error(self, case_id):
        with session_scope() as session:
            with pytest.raises(ValueError, match="Invalid custody action"):
                record_manual_event(
                    session=session,
                    case_id=case_id,
                    action="NONEXISTENT_ACTION",
                    actor_id="Officer Dave",
                )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Exports (JSON & CSV)
# ─────────────────────────────────────────────────────────────────────────────

class TestCustodyLedgerExport:

    def test_export_json_structure(self, case_id):
        with session_scope() as session:
            record_manual_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.CUSTODY_TRANSFERRED,
                actor_id="Officer Alice",
                reason="Court handoff",
            )

        with session_scope() as session:
            raw_json = export_custody_ledger_json(session, case_id)

        data = json.loads(raw_json)
        assert "export_metadata" in data
        assert "events" in data

        meta = data["export_metadata"]
        assert meta["case_id"] == case_id
        assert meta["total_events"] == 2  # CASE_CREATED + CUSTODY_TRANSFERRED
        assert meta["verification_result"] == "VALID"
        assert meta["verification_errors"] == []
        assert len(meta["genesis_event_hash"]) == 64
        assert len(meta["latest_event_hash"]) == 64
        assert "tamper-evident" in meta["disclaimer"].lower()

        events = data["events"]
        assert len(events) == 2
        assert events[0]["sequence"] == 1
        assert events[0]["action"] == "CASE_CREATED"
        assert events[0]["previous_event_hash"] is None
        assert events[1]["sequence"] == 2
        assert events[1]["action"] == "CUSTODY_TRANSFERRED"
        assert events[1]["previous_event_hash"] == events[0]["event_hash"]

    def test_export_csv_structure(self, case_id):
        with session_scope() as session:
            record_manual_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.CUSTODY_TRANSFERRED,
                actor_id="Officer Bob",
                reason="Transfer to secure evidence storage room",
            )

        with session_scope() as session:
            csv_text = export_custody_ledger_csv(session, case_id)

        lines = [line for line in csv_text.strip().split("\n") if line]
        assert len(lines) == 3  # Header + 2 events

        header = lines[0].split(",")
        assert header[0] == "Sequence"
        assert header[2] == "Action"
        assert header[3] == "Actor"
        assert header[9] == "Event Hash"

        assert "CASE_CREATED" in lines[1]
        assert "CUSTODY_TRANSFERRED" in lines[2]
        assert "Officer Bob" in lines[2]


# ─────────────────────────────────────────────────────────────────────────────
# 5. Queries & Evidence Filtering
# ─────────────────────────────────────────────────────────────────────────────

class TestCustodyQueries:

    def test_get_chain_for_case_order(self, case_id):
        with session_scope() as session:
            for i in range(3):
                record_event(
                    session=session,
                    case_id=case_id,
                    action=CustodyAction.ANALYST_NOTE,
                    actor_id="Analyst",
                    reason=f"Step {i}",
                )

        with session_scope() as session:
            events = get_chain_for_case(session, case_id)
            assert len(events) == 4
            for i in range(len(events) - 1):
                assert events[i].action_timestamp_utc <= events[i + 1].action_timestamp_utc

    def test_get_chain_for_evidence_filters_correctly(self, case_id):
        from forensiq.models.evidence import EvidenceItem
        from forensiq.utils.utc_utils import now_utc
        ev_id_1 = "00000000-0000-0000-0000-000000000001"
        ev_id_2 = "00000000-0000-0000-0000-000000000002"

        with session_scope() as session:
            session.add(EvidenceItem(
                id=ev_id_1,
                case_id=case_id,
                evidence_number="EVD-001",
                source_filename="cam1.mp4",
                sanitized_filename="cam1.mp4",
                imported_by="Analyst",
                imported_at_utc=now_utc(),
            ))
            session.add(EvidenceItem(
                id=ev_id_2,
                case_id=case_id,
                evidence_number="EVD-002",
                source_filename="cam2.mp4",
                sanitized_filename="cam2.mp4",
                imported_by="Analyst",
                imported_at_utc=now_utc(),
            ))
            session.flush()

            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                evidence_id=ev_id_1,
                actor_id="Analyst",
            )
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.EVIDENCE_IMPORTED,
                evidence_id=ev_id_2,
                actor_id="Analyst",
            )
            record_event(
                session=session,
                case_id=case_id,
                action=CustodyAction.HASH_CALCULATED,
                evidence_id=ev_id_1,
                actor_id="Analyst",
            )

        with session_scope() as session:
            ev1_events = get_chain_for_evidence(session, ev_id_1)
            ev2_events = get_chain_for_evidence(session, ev_id_2)

            assert len(ev1_events) == 2
            assert len(ev2_events) == 1
            assert all(e.evidence_id == ev_id_1 for e in ev1_events)
            assert all(e.evidence_id == ev_id_2 for e in ev2_events)


# ─────────────────────────────────────────────────────────────────────────────
# 6. UI Smoke Tests (Headless)
# ─────────────────────────────────────────────────────────────────────────────

class TestCustodyReportPageUI:

    @pytest.fixture
    def qapp(self):
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is None:
            app = QApplication([])
        return app

    def test_page_instantiation_no_active_case(self, qapp):
        from forensiq.ui.pages.custody_report_page import CustodyReportPage

        class MockMainWindow:
            active_case_id = None
            def update_chain_status(self, status): pass

        mock_mw = MockMainWindow()
        page = CustodyReportPage(main_window=mock_mw)
        page.refresh()

        assert not page._no_case_panel.isHidden()
        assert not page._verify_btn.isEnabled()
        assert not page._record_btn.isEnabled()
        assert page._table.rowCount() == 0

    def test_page_refresh_with_active_case(self, qapp, case_id):
        from forensiq.ui.pages.custody_report_page import CustodyReportPage

        recorded_statuses = []

        class MockMainWindow:
            active_case_id = case_id
            def update_chain_status(self, status):
                recorded_statuses.append(status)

        mock_mw = MockMainWindow()
        page = CustodyReportPage(main_window=mock_mw)
        page.refresh()

        assert page._no_case_panel.isHidden()
        assert page._verify_btn.isEnabled()
        assert page._record_btn.isEnabled()
        # Case has 1 genesis event
        assert page._table.rowCount() == 1
        assert "CHAIN INTACT" in page._status_badge.text()
        assert "VALID" in recorded_statuses

    def test_main_window_header_indicator_updates(self, qapp):
        from forensiq.ui.main_window import MainWindow
        mw = MainWindow()
        mw.update_chain_status("VALID")
        assert "INTACT" in mw._header_integrity.text()

        mw.update_chain_status("INVALID_EVENT_HASH")
        assert "COMPROMISED" in mw._header_integrity.text()

        mw.update_chain_status("EMPTY_CHAIN")
        assert "EMPTY" in mw._header_integrity.text()
