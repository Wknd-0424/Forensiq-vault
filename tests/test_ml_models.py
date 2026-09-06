"""
tests/test_ml_models.py
-----------------------
Unit and integration tests for ForensIQ Vault machine learning suite:
1. DVR Sector & Stream Byte Classifier (Dahua, Hikvision, TP-Link, Generic, Corrupt)
2. Surveillance Video Activity & Anomaly Classifier (Person, Vehicle, Motion, Scene Change, Anomaly)
3. Integration with recovery_service carving and ai_service triage
"""

import json
from pathlib import Path
import pytest
import numpy as np

from forensiq.constants import CustodyAction, EvidenceStatus, RecoveryStatus
from forensiq.database import init_db, session_scope
from forensiq.models.evidence import EvidenceItem, WorkingCopy
from forensiq.models.timeline import VideoSegment
from forensiq.services.case_service import create_case
from forensiq.services.ai_service import run_ai_triage
from forensiq.services.recovery_service import carve_video_stream
from forensiq.utils.utc_utils import now_utc

from forensiq.ml.features import (
    ACTIVITY_FEATURE_NAMES,
    SECTOR_FEATURE_NAMES,
    calculate_entropy,
    extract_activity_features,
    extract_sector_features,
)
from forensiq.ml.dvr_stream_classifier import (
    CLASSES as DVR_CLASSES,
    DVRStreamClassifier,
    get_dvr_classifier,
    predict_sector_class,
)
from forensiq.ml.surveillance_activity_classifier import (
    ACTIVITY_CLASSES,
    SurveillanceActivityClassifier,
    classify_surveillance_activity,
    get_activity_classifier,
)


@pytest.fixture(autouse=True)
def isolate_env(tmp_path, monkeypatch):
    """Isolate DB and Vault paths for each test."""
    db_url = f"sqlite:///{tmp_path / 'test_ml.db'}"
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


class TestFeatureExtraction:
    """Tests for raw byte and activity feature extractors."""

    def test_calculate_entropy_pure_zeros(self):
        data = b"\x00" * 1024
        assert calculate_entropy(data) == 0.0

    def test_calculate_entropy_empty(self):
        assert calculate_entropy(b"") == 0.0

    def test_calculate_entropy_uniform_distribution(self):
        data = bytes(range(256)) * 4
        entropy = calculate_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_extract_sector_features_dimensions(self):
        sample = b"DHAV\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x67\x42\x00\x1f"
        feat = extract_sector_features(sample)
        assert len(feat) == len(SECTOR_FEATURE_NAMES)
        assert feat.dtype == np.float32

    def test_extract_sector_features_empty(self):
        feat = extract_sector_features(b"")
        assert np.all(feat == 0.0)

    def test_extract_activity_features_dimensions(self):
        metrics = {
            "motion_score": 0.75,
            "aspect_ratio": 2.1,
            "area_ratio": 0.15,
            "luminance_delta": 0.08,
            "temporal_velocity": 0.45,
            "histogram_shift": 0.10,
            "anomaly_score": 0.05,
        }
        feat = extract_activity_features(metrics)
        assert len(feat) == len(ACTIVITY_FEATURE_NAMES)
        assert feat[0] == 0.75
        assert feat[1] == 2.1


class TestDVRStreamClassifier:
    """Tests for the trained DVR byte-stream classifier."""

    def test_classifier_is_trained(self):
        clf = get_dvr_classifier()
        assert clf.is_trained is True

    def test_predict_dahua_stream(self):
        # Dahua signature + SPS NAL unit
        dahua_sample = (
            b"DAHUADHAV\x01\x00\x00\x00\x20\x26\x09\x06\x10\x30\x00\x00"
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"
            b"\x00\x00\x00\x01\x68\xce\x3c\x80"
            b"\x00\x00\x00\x01\x65\x88\x84\x00"
        )
        cls_name, conf = predict_sector_class(dahua_sample)
        assert cls_name == "DAHUA_STREAM"
        assert conf >= 0.70

    def test_predict_hikvision_stream(self):
        hik_sample = (
            b"HIKVISION\x00\x01HKAA\x00\x02\x20\x26\x09\x06\x10\x30\x00\x00"
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"
            b"\x00\x00\x00\x01\x68\xce\x3c\x80"
        )
        cls_name, conf = predict_sector_class(hik_sample)
        assert cls_name == "HIKVISION_STREAM"
        assert conf >= 0.70

    def test_predict_tplink_onvif_stream(self):
        tplink_sample = (
            b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2avc1mp41"
            b"\x00\x00\x00\x30udta\x00\x00\x00\x28nameTP-Link VIGI C340 ONVIF Profile S"
            b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"
        )
        cls_name, conf = predict_sector_class(tplink_sample)
        assert cls_name == "TPLINK_ONVIF_STREAM"
        assert conf >= 0.60

    def test_predict_corrupt_noise(self):
        zeros = b"\x00" * 1024
        cls_name, conf = predict_sector_class(zeros)
        assert cls_name == "CORRUPT_NOISE"
        assert conf >= 0.80

    def test_predict_proba_sums_to_one(self):
        sample = b"RANDOM_BYTE_STREAM_FOR_PROBABILITY_TEST" * 10
        clf = get_dvr_classifier()
        probs = clf.predict_proba(sample)
        assert len(probs) == len(DVR_CLASSES)
        assert abs(sum(probs.values()) - 1.0) < 0.01


class TestSurveillanceActivityClassifier:
    """Tests for the trained surveillance activity triage classifier."""

    def test_activity_classifier_is_trained(self):
        clf = get_activity_classifier()
        assert clf.is_trained is True

    def test_classify_person(self):
        # Vertical silhouette (aspect_ratio ~0.35) with pedestrian motion
        metrics = {
            "motion_score": 0.55,
            "aspect_ratio": 0.35,
            "area_ratio": 0.04,
            "luminance_delta": 0.05,
            "temporal_velocity": 0.22,
            "histogram_shift": 0.07,
            "anomaly_score": 0.10,
        }
        cls_name, conf = classify_surveillance_activity(metrics)
        assert cls_name == "person"
        assert conf >= 0.70

    def test_classify_vehicle(self):
        # Horizontal geometry (aspect_ratio ~2.0) with high area & velocity
        metrics = {
            "motion_score": 0.75,
            "aspect_ratio": 2.0,
            "area_ratio": 0.22,
            "luminance_delta": 0.10,
            "temporal_velocity": 0.65,
            "histogram_shift": 0.12,
            "anomaly_score": 0.15,
        }
        cls_name, conf = classify_surveillance_activity(metrics)
        assert cls_name == "vehicle"
        assert conf >= 0.70

    def test_classify_scene_change(self):
        # Sudden massive luminance and histogram shift
        metrics = {
            "motion_score": 0.85,
            "aspect_ratio": 1.0,
            "area_ratio": 0.65,
            "luminance_delta": 0.80,
            "temporal_velocity": 0.10,
            "histogram_shift": 0.85,
            "anomaly_score": 0.50,
        }
        cls_name, conf = classify_surveillance_activity(metrics)
        assert cls_name == "scene_change"
        assert conf >= 0.70

    def test_classify_anomaly(self):
        # Severe outlier anomaly score
        metrics = {
            "motion_score": 0.65,
            "aspect_ratio": 0.85,
            "area_ratio": 0.15,
            "luminance_delta": 0.25,
            "temporal_velocity": 0.40,
            "histogram_shift": 0.28,
            "anomaly_score": 0.92,
        }
        cls_name, conf = classify_surveillance_activity(metrics)
        assert cls_name == "anomaly"
        assert conf >= 0.70


class TestMLServiceIntegration:
    """Integration tests verifying that ai_service and recovery_service use the ML models."""

    def test_ai_service_uses_ml_activity_classifier(self, tmp_path):
        with session_scope() as session:
            case = create_case(session, "CASE-ML-01", "ML Test Case", "Investigator A")
            ev = EvidenceItem(
                case_id=case.id,
                evidence_number="EX-ML-01",
                source_filename="camera1.mp4",
                sanitized_filename="camera1.mp4",
                file_size_bytes=1024,
                original_sha256="1111111111111111111111111111111111111111111111111111111111111111",
                status=EvidenceStatus.WORKING_COPY_READY.value,
                imported_by="Investigator A",
                imported_at_utc=now_utc(),
            )
            session.add(ev)
            session.flush()

            segment = VideoSegment(
                evidence_id=ev.id,
                channel_id="CH-01",
                duration_seconds=20.0,
                parse_status="PARSED",
            )
            session.add(segment)
            session.commit()

            detections = run_ai_triage(
                session=session,
                segment_id=segment.id,
                actor_id="Investigator A",
                confidence_threshold=0.5,
            )

            assert len(detections) >= 1
            # Check model name indicates the trained ML model
            assert "ML-Activity-Classifier" in detections[0].model_name

    def test_recovery_service_manifest_includes_ml_sector_class(self, tmp_path):
        with session_scope() as session:
            case = create_case(session, "CASE-ML-02", "ML Carve Case", "Investigator B")
            ev = EvidenceItem(
                case_id=case.id,
                evidence_number="EX-ML-02",
                source_filename="dahua_dump.raw",
                sanitized_filename="dahua_dump.raw",
                file_size_bytes=2048,
                original_sha256="3333333333333333333333333333333333333333333333333333333333333333",
                status=EvidenceStatus.WORKING_COPY_READY.value,
                imported_by="Investigator B",
                imported_at_utc=now_utc(),
            )
            session.add(ev)
            session.flush()

            # Create working copy with Dahua stream
            wc_dir = tmp_path / "vault" / case.id / "evidence" / ev.id / "working_copy"
            wc_dir.mkdir(parents=True, exist_ok=True)
            wc_file = wc_dir / "dahua_dump.raw"

            dahua_stream = (
                b"DAHUADHAV\x01\x00\x00\x00\x20\x26\x09\x06\x10\x30\x00\x00"
                b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda"
                b"\x00\x00\x00\x01\x68\xce\x3c\x80"
                b"\x00\x00\x00\x01\x65\x88\x84\x00\xff"
                b"\x00\x00\x01\x41\x9a\x01\x02"
                b"\x00\x00\x01\x41\x9a\x01\x03"
                b"\x00\x00\x01\x41\x9a\x01\x04"
                b"\x00\x00\x01\x41\x9a\x01\x05"
                b"\x00\x00\x01\x41\x9a\x01\x06"
            )
            wc_file.write_bytes(dahua_stream)

            wc = WorkingCopy(
                evidence_id=ev.id,
                relative_path=str(wc_file.relative_to(tmp_path / "vault")),
                sha256="3333333333333333333333333333333333333333333333333333333333333333",
                created_at_utc=now_utc(),
                verification_status="VERIFIED",
            )
            session.add(wc)
            session.commit()

            rec_res, deriv_path = carve_video_stream(session, ev.id, actor_id="Investigator B")
            assert rec_res.status == RecoveryStatus.COMPLETE.value
            assert deriv_path is not None

            # Verify manifest has ML metadata
            manifest_path = deriv_path.with_name(f"{deriv_path.name}.manifest.json")
            assert manifest_path.exists()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            assert manifest["ml_sector_class"] == "DAHUA_STREAM"
            assert manifest["ml_confidence"] >= 0.60
