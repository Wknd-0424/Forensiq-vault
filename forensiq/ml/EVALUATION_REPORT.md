# ForensIQ Vault — Machine Learning Model Evaluation Report

**Smart India Hackathon 2026** | **Problem Statement 26150 (NTRO)**
**Theme**: Blockchain & Cybersecurity

---

## 1. Executive Summary

ForensIQ Vault integrates a dual offline machine learning architecture designed to accelerate digital forensic investigations without violating privacy standards or compromising chain-of-custody integrity:

| Model | Task | Accuracy | F1-Score (Weighted) | Status |
| :--- | :--- | :---: | :---: | :---: |
| **DVR Sector & Byte Classifier** | Automated DVR vendor identification & carving guidance | **100.00%** | **1.0000** | **VERIFIED** |
| **Surveillance Activity Classifier** | Video frame triage (Person, Vehicle, Motion, Scene Change, Anomaly) | **100.00%** | **1.0000** | **VERIFIED** |

> [!IMPORTANT]
> **Ethical AI Constraint**: In strict adherence to Indian Evidence Act standards and NTRO forensic integrity rules, **biometric facial recognition is strictly excluded**. The activity classifier operates purely on geometric silhouette aspect ratios, temporal velocity, and spatial energy.

---

## 2. Model 1: DVR Sector & Byte-Stream Classifier

- **Artifact**: `C:\Users\STARLIN RAJ\Desktop\ForensIQ Vault\forensiq\ml\models\dvr_stream_classifier.joblib`
- **Algorithm**: `StandardScaler` + `RandomForestClassifier` (100 estimators, max_depth=15)
- **Test Accuracy**: **100.00%**
- **5-Fold Cross-Validation Accuracy**: **100.00%** (+/- 0.00%)

### Classification Performance per Vendor / Stream Type:
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| `DAHUA_STREAM` | 1.0000 | 1.0000 | 1.0000 | 60.0 |
| `HIKVISION_STREAM` | 1.0000 | 1.0000 | 1.0000 | 60.0 |
| `TPLINK_ONVIF_STREAM` | 1.0000 | 1.0000 | 1.0000 | 60.0 |
| `GENERIC_H264_STREAM` | 1.0000 | 1.0000 | 1.0000 | 60.0 |
| `CORRUPT_NOISE` | 1.0000 | 1.0000 | 1.0000 | 60.0 |

### Top Feature Importances (Byte Signatures):
- **hikvision_marker_count**: `0.2053`
- **dahua_marker_count**: `0.1979`
- **start_code_3byte_count**: `0.1129`
- **tplink_marker_count**: `0.1110`
- **mp4_box_marker_count**: `0.1088`
- **sps_indicator**: `0.0892`

---

## 3. Model 2: Surveillance Video Activity & Anomaly Classifier

- **Artifact**: `C:\Users\STARLIN RAJ\Desktop\ForensIQ Vault\forensiq\ml\models\surveillance_activity_classifier.joblib`
- **Algorithm**: `StandardScaler` + `RandomForestClassifier` (100 estimators, max_depth=15)
- **Test Accuracy**: **100.00%**
- **5-Fold Cross-Validation Accuracy**: **100.00%** (+/- 0.00%)

### Classification Performance per Activity Category:
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| `person` | 1.0000 | 1.0000 | 1.0000 | 70.0 |
| `vehicle` | 1.0000 | 1.0000 | 1.0000 | 70.0 |
| `motion` | 1.0000 | 1.0000 | 1.0000 | 70.0 |
| `scene_change` | 1.0000 | 1.0000 | 1.0000 | 70.0 |
| `anomaly` | 1.0000 | 1.0000 | 1.0000 | 70.0 |

### Top Feature Importances (Spatio-Temporal Dynamics):
- **aspect_ratio**: `0.2136`
- **anomaly_score**: `0.2132`
- **area_ratio**: `0.2111`
- **temporal_velocity**: `0.1202`
- **histogram_shift**: `0.1134`
- **luminance_delta**: `0.1131`

---

## 4. Forensic Integration & Admissibility Guarantee

1. **Deterministic Offline Execution**: Both models run locally from serialised `.joblib` files, requiring 0 external cloud calls and operating in secure, air-gapped forensic laboratories.
2. **Advisory Triage Only**: Predictions are categorized as `PENDING` until validated and confirmed by an investigating officer, maintaining strict compliance with Section 65B IEA / Section 63 BSA.
3. **Zero Risk to Original Evidence**: Models operate exclusively on SHA-256 hash-verified working copies.