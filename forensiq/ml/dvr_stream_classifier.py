"""
forensiq/ml/dvr_stream_classifier.py
------------------------------------
Machine learning classifier for proprietary DVR stream and raw sector identification.

Classes:
  - DAHUA_STREAM: Dahua DHAV / DHFS streams
  - HIKVISION_STREAM: Hikvision HIK / HKAA / HKBB streams
  - TPLINK_ONVIF_STREAM: TP-Link VIGI / Tapo / ONVIF Profile S
  - GENERIC_H264_STREAM: Standard Annex-B H.264 / H.265 / MP4
  - CORRUPT_NOISE: Wiped, encrypted, or severely corrupted unallocated sectors
"""

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from forensiq.ml.features import extract_sector_features

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "dvr_stream_classifier.joblib"

CLASSES: list[str] = [
    "DAHUA_STREAM",
    "HIKVISION_STREAM",
    "TPLINK_ONVIF_STREAM",
    "GENERIC_H264_STREAM",
    "CORRUPT_NOISE",
]


class DVRStreamClassifier:
    """Trained machine learning classifier for DVR sector identification."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.model = None
        self._load()

    def _load(self) -> None:
        """Load trained scikit-learn model pipeline if available."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Loaded DVRStreamClassifier from %s", self.model_path)
            except Exception as e:
                logger.warning("Could not load DVRStreamClassifier: %s. Using heuristic fallback.", e)
                self.model = None
        else:
            logger.debug("DVRStreamClassifier model file not found at %s. Using fallback.", self.model_path)
            self.model = None

    @property
    def is_trained(self) -> bool:
        """Return True if model is loaded and ready."""
        return self.model is not None

    def predict(self, data: bytes) -> tuple[str, float]:
        """
        Predict DVR stream/sector class and return (class_name, confidence).
        """
        if not data:
            return "CORRUPT_NOISE", 1.0

        features = extract_sector_features(data).reshape(1, -1)

        if self.model is not None:
            try:
                probs = self.model.predict_proba(features)[0]
                classes = self.model.classes_
                best_idx = int(np.argmax(probs))
                return str(classes[best_idx]), float(probs[best_idx])
            except Exception as e:
                logger.warning("ML prediction failed (%s); using fallback.", e)

        # Statistical rule fallback
        return self._fallback_predict(data, features[0])

    def predict_proba(self, data: bytes) -> dict[str, float]:
        """Return confidence probabilities across all supported classes."""
        if not data:
            return {c: (1.0 if c == "CORRUPT_NOISE" else 0.0) for c in CLASSES}

        features = extract_sector_features(data).reshape(1, -1)
        if self.model is not None:
            try:
                probs = self.model.predict_proba(features)[0]
                classes = self.model.classes_
                return {str(cls): float(prob) for cls, prob in zip(classes, probs)}
            except Exception:
                pass

        best_cls, best_conf = self._fallback_predict(data, features[0])
        res = {c: 0.05 for c in CLASSES}
        res[best_cls] = best_conf
        # Normalize
        tot = sum(res.values())
        return {c: v / tot for c, v in res.items()}

    def _fallback_predict(self, data: bytes, feat: np.ndarray) -> tuple[str, float]:
        """High-precision fallback when serialized model is absent."""
        entropy = feat[0]
        zero_ratio = feat[3]
        start_codes = feat[7] + feat[8]
        dahua_count = feat[12]
        hik_count = feat[13]
        tplink_count = feat[14]

        if dahua_count > 0:
            return "DAHUA_STREAM", 0.95
        if hik_count > 0:
            return "HIKVISION_STREAM", 0.95
        if tplink_count > 0:
            return "TPLINK_ONVIF_STREAM", 0.92
        if start_codes >= 1 and entropy > 3.5:
            return "GENERIC_H264_STREAM", 0.88
        if zero_ratio > 0.85 or entropy < 2.0 or entropy > 7.95:
            return "CORRUPT_NOISE", 0.90

        return "GENERIC_H264_STREAM", 0.60


_DEFAULT_CLASSIFIER: Optional[DVRStreamClassifier] = None


def get_dvr_classifier() -> DVRStreamClassifier:
    """Return the global DVRStreamClassifier singleton."""
    global _DEFAULT_CLASSIFIER
    if _DEFAULT_CLASSIFIER is None:
        _DEFAULT_CLASSIFIER = DVRStreamClassifier()
    return _DEFAULT_CLASSIFIER


def predict_sector_class(data: bytes) -> tuple[str, float]:
    """Convenience helper to predict class and confidence for a raw byte chunk."""
    return get_dvr_classifier().predict(data)
