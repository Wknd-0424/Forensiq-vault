"""
forensiq/ml/features.py
-----------------------
Feature extraction engines for forensic ML models:
1. DVR Sector / Stream Byte Features: Entropy, byte distribution, start-code frequencies,
   and proprietary vendor magic pattern counts.
2. Surveillance Activity Features: Motion dynamics, bounding box geometry, temporal
   velocity, and luminance shifts. (Biometric face recognition strictly excluded).
"""

import math
from typing import Any, Sequence
import numpy as np


SECTOR_FEATURE_NAMES: list[str] = [
    "entropy",
    "byte_mean",
    "byte_std",
    "zero_ratio",
    "high_byte_ratio",
    "ascii_ratio",
    "max_zero_run_ratio",
    "start_code_3byte_count",
    "start_code_4byte_count",
    "sps_indicator",
    "pps_indicator",
    "idr_indicator",
    "dahua_marker_count",
    "hikvision_marker_count",
    "tplink_marker_count",
    "mp4_box_marker_count",
]

ACTIVITY_FEATURE_NAMES: list[str] = [
    "motion_score",
    "aspect_ratio",
    "area_ratio",
    "luminance_delta",
    "temporal_velocity",
    "histogram_shift",
    "anomaly_score",
]


def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return float(entropy)


def extract_sector_features(data: bytes) -> np.ndarray:
    """
    Extract a 16-dimensional standardized feature vector from raw DVR sector/stream bytes.

    Features:
      0: Shannon entropy (0 to 8)
      1: Byte mean normalized (0 to 1)
      2: Byte standard deviation normalized (0 to 1)
      3: Ratio of 0x00 bytes
      4: Ratio of bytes > 127
      5: Ratio of printable ASCII bytes (0x20 to 0x7E)
      6: Maximum continuous zero-byte run ratio
      7: 3-byte Annex-B start code count (0x000001)
      8: 4-byte Annex-B start code count (0x00000001)
      9: H.264 SPS indicator (type 7)
     10: H.264 PPS indicator (type 8)
     11: H.264 IDR keyframe indicator (type 5)
     12: Dahua proprietary markers count (DHAV, DAHUA, DHFS)
     13: Hikvision proprietary markers count (HIKVISION, HKAA, HKBB, HKSYS)
     14: TP-Link/ONVIF markers count (VIGI, Tapo, ONVIF)
     15: MP4 ISO box markers count (ftyp, moov, mdat, free)
    """
    if not data:
        return np.zeros(len(SECTOR_FEATURE_NAMES), dtype=np.float32)

    total_len = len(data)
    entropy = calculate_entropy(data)

    # Byte stats
    arr = np.frombuffer(data, dtype=np.uint8)
    byte_mean = float(np.mean(arr)) / 255.0
    byte_std = float(np.std(arr)) / 128.0
    zero_ratio = float(np.count_nonzero(arr == 0)) / total_len
    high_byte_ratio = float(np.count_nonzero(arr > 127)) / total_len
    ascii_ratio = float(np.count_nonzero((arr >= 32) & (arr <= 126))) / total_len

    # Longest run of zeros
    max_zero_run = 0
    current_run = 0
    for b in data:
        if b == 0:
            current_run += 1
            if current_run > max_zero_run:
                max_zero_run = current_run
        else:
            current_run = 0
    max_zero_run_ratio = min(1.0, max_zero_run / max(1, total_len))

    # Annex-B start codes
    start_3_count = data.count(b"\x00\x00\x01")
    start_4_count = data.count(b"\x00\x00\x00\x01")

    # NAL types
    sps_found = 1.0 if (b"\x00\x00\x00\x01\x67" in data or b"\x00\x00\x01\x67" in data or b"\x00\x00\x00\x01\x42" in data) else 0.0
    pps_found = 1.0 if (b"\x00\x00\x00\x01\x68" in data or b"\x00\x00\x01\x68" in data or b"\x00\x00\x00\x01\x44" in data) else 0.0
    idr_found = 1.0 if (b"\x00\x00\x00\x01\x65" in data or b"\x00\x00\x01\x65" in data or b"\x00\x00\x00\x01\x26" in data) else 0.0

    # Vendor signatures
    dahua_count = (
        data.count(b"DHAV") + data.count(b"DAHUA") + data.count(b"DHFS")
    )
    hik_count = (
        data.count(b"HIKVISION") + data.count(b"HKAA") + data.count(b"HKBB") + data.count(b"HKSYS")
    )
    tplink_count = (
        data.count(b"VIGI") + data.count(b"Tapo") + data.count(b"ONVIF")
    )
    mp4_count = (
        data.count(b"ftyp") + data.count(b"moov") + data.count(b"mdat") + data.count(b"free")
    )

    vec = [
        entropy,
        byte_mean,
        byte_std,
        zero_ratio,
        high_byte_ratio,
        ascii_ratio,
        max_zero_run_ratio,
        float(min(start_3_count, 50)),
        float(min(start_4_count, 50)),
        sps_found,
        pps_found,
        idr_found,
        float(min(dahua_count, 20)),
        float(min(hik_count, 20)),
        float(min(tplink_count, 20)),
        float(min(mp4_count, 20)),
    ]
    return np.array(vec, dtype=np.float32)


def extract_activity_features(metrics: dict[str, Any]) -> np.ndarray:
    """
    Extract a 7-dimensional standardized feature vector for surveillance activity classification.

    Expected input dict keys (with sensible fallbacks):
      - motion_score: float (0.0 to 1.0)
      - aspect_ratio: float (width / height). For person silhouette ~0.2-0.5, vehicle ~1.0-3.0
      - area_ratio: float (bbox area / frame area)
      - luminance_delta: float (0.0 to 1.0)
      - temporal_velocity: float (pixels or normalized distance moved per frame)
      - histogram_shift: float (0.0 to 1.0)
      - anomaly_score: float (0.0 to 1.0)
    """
    motion = float(metrics.get("motion_score", 0.0))
    aspect = float(metrics.get("aspect_ratio", 1.0))
    area = float(metrics.get("area_ratio", 0.05))
    lum = float(metrics.get("luminance_delta", 0.0))
    vel = float(metrics.get("temporal_velocity", 0.0))
    hist = float(metrics.get("histogram_shift", 0.0))
    anomaly = float(metrics.get("anomaly_score", 0.0))

    vec = [motion, aspect, area, lum, vel, hist, anomaly]
    return np.array(vec, dtype=np.float32)
