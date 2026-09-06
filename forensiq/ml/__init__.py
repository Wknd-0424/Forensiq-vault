"""
forensiq/ml/__init__.py
-----------------------
Forensic Machine Learning Package for ForensIQ Vault.

Exposes:
  - DVRStreamClassifier: Byte-level ML classifier for proprietary DVR sectors & streams.
  - SurveillanceActivityClassifier: Video activity & anomaly triage classifier.
  - Feature extraction utilities for sectors and video metrics.
"""

from forensiq.ml.dvr_stream_classifier import (
    CLASSES as DVR_CLASSES,
    DVRStreamClassifier,
    get_dvr_classifier,
    predict_sector_class,
)
from forensiq.ml.features import (
    ACTIVITY_FEATURE_NAMES,
    SECTOR_FEATURE_NAMES,
    calculate_entropy,
    extract_activity_features,
    extract_sector_features,
)
from forensiq.ml.surveillance_activity_classifier import (
    ACTIVITY_CLASSES,
    SurveillanceActivityClassifier,
    classify_surveillance_activity,
    get_activity_classifier,
)

__all__ = [
    "DVR_CLASSES",
    "ACTIVITY_CLASSES",
    "SECTOR_FEATURE_NAMES",
    "ACTIVITY_FEATURE_NAMES",
    "DVRStreamClassifier",
    "SurveillanceActivityClassifier",
    "get_dvr_classifier",
    "get_activity_classifier",
    "predict_sector_class",
    "classify_surveillance_activity",
    "extract_sector_features",
    "extract_activity_features",
    "calculate_entropy",
]
