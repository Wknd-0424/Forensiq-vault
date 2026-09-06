"""
forensiq/ml/surveillance_activity_classifier.py
-----------------------------------------------
Machine learning classifier for surveillance video activity and anomaly triage.

Target Classes:
  - person: Pedestrian / individual presence (vertical aspect silhouette + movement)
  - vehicle: Automobile, truck, motorbike presence (horizontal aspect geometry + velocity)
  - motion: General environmental or object motion
  - scene_change: Camera tampering, occlusion, lighting shift, or sudden transition
  - anomaly: Temporal/spatial outlier deviations

CRITICAL FORENSIC INVARIANT:
  Biometric facial recognition is STRICTLY PROHIBITED.
  This model classifies activity based strictly on spatio-temporal dynamics and geometry.
"""

import logging
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np

from forensiq.ml.features import extract_activity_features

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "surveillance_activity_classifier.joblib"

ACTIVITY_CLASSES: list[str] = [
    "person",
    "vehicle",
    "motion",
    "scene_change",
    "anomaly",
]


class SurveillanceActivityClassifier:
    """Trained machine learning classifier for forensic surveillance video triage."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.model = None
        self._load()

    def _load(self) -> None:
        """Load trained model pipeline from disk if available."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Loaded SurveillanceActivityClassifier from %s", self.model_path)
            except Exception as e:
                logger.warning("Could not load SurveillanceActivityClassifier: %s. Using fallback.", e)
                self.model = None
        else:
            logger.debug("SurveillanceActivityClassifier model file not found at %s. Using fallback.", self.model_path)
            self.model = None

    @property
    def is_trained(self) -> bool:
        """Return True if model is loaded and ready."""
        return self.model is not None

    def classify(self, metrics: dict[str, Any]) -> tuple[str, float]:
        """
        Classify surveillance video activity from extracted frame metrics.
        Returns (predicted_class, confidence).
        """
        features = extract_activity_features(metrics).reshape(1, -1)

        if self.model is not None:
            try:
                probs = self.model.predict_proba(features)[0]
                classes = self.model.classes_
                best_idx = int(np.argmax(probs))
                return str(classes[best_idx]), float(probs[best_idx])
            except Exception as e:
                logger.warning("Activity ML prediction failed (%s); using fallback.", e)

        return self._fallback_classify(metrics)

    def classify_proba(self, metrics: dict[str, Any]) -> dict[str, float]:
        """Return confidence probabilities across all activity classes."""
        features = extract_activity_features(metrics).reshape(1, -1)

        if self.model is not None:
            try:
                probs = self.model.predict_proba(features)[0]
                classes = self.model.classes_
                return {str(cls): float(prob) for cls, prob in zip(classes, probs)}
            except Exception:
                pass

        best_cls, best_conf = self._fallback_classify(metrics)
        res = {c: 0.05 for c in ACTIVITY_CLASSES}
        res[best_cls] = best_conf
        tot = sum(res.values())
        return {c: v / tot for c, v in res.items()}

    def _fallback_classify(self, metrics: dict[str, Any]) -> tuple[str, float]:
        """Deterministic rule-based fallback when model file is not yet trained."""
        motion = float(metrics.get("motion_score", 0.0))
        aspect = float(metrics.get("aspect_ratio", 1.0))
        lum_delta = float(metrics.get("luminance_delta", 0.0))
        anomaly_score = float(metrics.get("anomaly_score", 0.0))

        if lum_delta > 0.45:
            return "scene_change", 0.85
        if anomaly_score > 0.65:
            return "anomaly", 0.80
        if motion > 0.25:
            if aspect < 0.6:
                # Vertical silhouette -> person
                return "person", 0.82
            elif aspect > 1.2:
                # Horizontal silhouette -> vehicle
                return "vehicle", 0.84
            return "motion", 0.75

        return "motion", 0.50


_DEFAULT_ACTIVITY_CLASSIFIER: Optional[SurveillanceActivityClassifier] = None


def get_activity_classifier() -> SurveillanceActivityClassifier:
    """Return the global SurveillanceActivityClassifier singleton."""
    global _DEFAULT_ACTIVITY_CLASSIFIER
    if _DEFAULT_ACTIVITY_CLASSIFIER is None:
        _DEFAULT_ACTIVITY_CLASSIFIER = SurveillanceActivityClassifier()
    return _DEFAULT_ACTIVITY_CLASSIFIER


def classify_surveillance_activity(metrics: dict[str, Any]) -> tuple[str, float]:
    """Convenience helper to classify surveillance video activity metrics."""
    return get_activity_classifier().classify(metrics)
