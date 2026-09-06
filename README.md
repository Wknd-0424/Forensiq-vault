# ForensIQ Vault 🛡️

**Multi-Vendor DVR/NVR Forensic Analysis Tool for Standardized Acquisition, Recovery, Analysis, Validation, and Reporting of Surveillance Evidence**

[![Smart India Hackathon 2026](https://img.shields.io/badge/SIH-2026-orange.svg)](https://www.sih.gov.in/)
[![Problem Statement ID](https://img.shields.io/badge/Problem%20Statement-26150-blue.svg)](#problem-statement)
[![Organization](https://img.shields.io/badge/Organization-NTRO-green.svg)](#organization)
[![Tests](https://img.shields.io/badge/Tests-228%20Passed-brightgreen.svg)](#test-suite)
[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![ML Models](https://img.shields.io/badge/ML%20Models-100%25%20F1--Score-brightgreen.svg)](#forensic-machine-learning-suite)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20(Qt%20for%20Python)-green.svg)](https://wiki.qt.io/Qt_for_Python)

---

## 📌 Problem Statement & Context

- **Event**: Smart India Hackathon 2026 (SIH 2026)
- **Problem Statement ID**: 26150
- **Organization**: National Technical Research Organisation (NTRO)
- **Theme**: Blockchain and Cybersecurity
- **Category**: Software

### The Forensic Challenge
Law enforcement and national security agencies routinely seize digital video recorders (DVRs) and network video recorders (NVRs) from crime scenes. Investigators face critical operational bottlenecks:
1. **Proprietary & Fragmented Formats**: CCTV vendors (Dahua, Hikvision, TP-Link, CP PLUS, etc.) use non-standard file wrappers (`.dav`, `.hkv`, `.raw`), custom packet headers, and proprietary timestamp encoding that standard video players cannot open.
2. **Evidence Spoliation Risks**: Parsing or viewing footage directly from original exhibits risks altering digital timestamps or file attributes, compromising admissibility under Section 65B of the Indian Evidence Act / Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023.
3. **Corrupted or Overwritten Footage**: Power cuts, physical impacts, or deliberate tampering leave files with damaged filesystem structures and fragmented streams.
4. **Clock Drift Across Multiple Cameras**: Surveillance systems in disparate areas have unsynchronized internal clocks, frustrating chronological multi-camera timeline reconstruction.
5. **Lack of Cryptographic Chain of Custody**: Evidence logs stored in flat files or spreadsheets can be tampered with undetected.

---

## 🏛️ ForensIQ Vault Architecture & Core Invariants

ForensIQ Vault is designed specifically around **digital forensics best practices** and **court admissibility standards**:

```
                               ┌──────────────────────────────────────────────┐
                               │             ForensIQ Vault UI                │
                               │        (PySide6 Forensic Dark QSS)           │
                               └───────┬──────────────────────────────┬───────┘
                                       │                              │
                    ┌──────────────────▼───────────┐    ┌─────────────▼────────────────┐
                    │     Evidence Ingestion       │    │   Cryptographic Audit Chain  │
                    │  - Streaming SHA-256 / MD5   │    │  - Merkle-like Hash Chains   │
                    │  - Read-Only Lock (0444)     │    │  - Canonical JSON Signing    │
                    │  - Atomic Companion Manifest │    │  - Tamper Detection Engine   │
                    └──────────────┬───────────────┘    └──────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   Immutable Vault Storage    │
                    │  vault/{case_id}/evidence/   │
                    │   ├── original/ (READ-ONLY)  │ ◄── STRICT INVARIANT: Original
                    │   ├── working_copy/ (ACTIVE) │     is never touched!
                    │   └── derivatives/           │
                    └──────────────┬───────────────┘
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       │                           │                           │
┌──────▼────────────────┐ ┌────────▼───────────────┐ ┌─────────▼────────────────┐
│ Multi-Vendor Adapters │ │ Video Carving Engine   │ │ Timeline & AI Triage      │
│ - Dahua DHAV / .dav   │ │ - Annex-B NAL Scanner  │ │ - Multi-Camera Clock Sync │
│ - Hikvision .hkv/HIK  │ │ - H.264 / H.265 SPS/IDR│ │ - Frame Activity Triage   │
│ - TP-Link VIGI / ONVIF│ │ - Reconstructed Stream │ │ - Ethical Constraints     │
│ - Generic Media / Fall│ │ - Mandatory Limitation │ │   (NO FACE RECOGNITION)   │
└───────────────────────┘ └────────────────────────┘ └───────────────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │ Court-Admissible Dossier Generation   │
                │ - Section 65B IEA / Sec 63 BSA Cert  │
                │ - Formats: HTML, JSON, A4 PDF        │
                │ - Companion Manifest + SHA-256 Seal  │
                └──────────────────────────────────────┘
```

### Forensic Invariants
1. **Original Evidence Immutability**: Original files are moved into `vault/{case_id}/evidence/{evidence_id}/original/` and permanently marked **read-only** (`chmod 0444`).
2. **Working Copy Isolation**: All decoding, carving, ffprobe metadata extraction, and AI triage operate strictly on hash-verified working copies (`vault/.../working_copy/`).
3. **Segregated Derivatives**: Any recovered video or transcoded stream is placed into a segregated `derivatives/` directory, independently hashed, assigned an atomic `.manifest.json`, and linked to its parent exhibit.
4. **Append-Only Hash-Chained Custody Ledger**: Every action (creation, import, verification, normalization, carving, report generation) forms a SHA-256 canonical JSON hash chain (`previous_event_hash -> event_hash`). Any manual database tampering breaks the chain immediately.
5. **No Invented Metadata**: If a proprietary DVR timestamp is missing or unparseable, it is marked `None` / `Unknown` with an explicit audit warning.
6. **Strict Ethical AI Policy**: Built-in AI triage supports object and activity detection (`person`, `vehicle`, `motion`, `scene_change`). **Biometric facial recognition is strictly prohibited and architecturally blocked**. All detections require mandatory human forensic review.
7. **Statutory Legal Compliance**: Reports include an automated electronic evidence certificate compliant with **Section 65B of the Indian Evidence Act, 1872** and **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023**.

---

## ✨ Key Features & Capabilities

| Module | Features & Capabilities |
| :--- | :--- |
| **Case Management** | Full case lifecycle tracking (ID, Case Number, Investigator, Agency, Status, Description) backed by SQLAlchemy 2.0 and SQLite. |
| **Evidence Ingestion** | Chunked streaming SHA-256 and MD5 calculation with live progress reporting, format validation, filename sanitization, read-only locking, and atomic companion manifests. |
| **Chain of Custody Ledger** | Sequential cryptographic ledger, mathematical tamper detection, manual event logging (handoffs, analyst notes), canonical JSON export, and RFC 4180 CSV export. |
| **Video Stream Analysis** | Non-destructive `ffprobe` metadata parsing on working copies, 4-part forensic validation sanity checks (codec consistency, future/past timestamp sanity, bitrate truncation, stream dimensions). |
| **Vendor Adapters** | Modular vendor profiles for **Dahua** (`DHAV`/`DAHUA`/`DHFS`), **Hikvision** (`HIKVISION`/`HKAA`/`HKBB`), **TP-Link VIGI/Tapo** (ONVIF Profile S), and **Generic Media** with automatic fallback to `UnknownSourceAdapter`. |
| **Video Carving Recovery** | Low-level byte-by-byte Annex-B NAL unit scanner (H.264 / H.265 SPS, PPS, VPS, IDR, Slices) extracting playable derivatives from wiped, damaged, or unallocated disk dumps. Guided by real-time ML sector classification. Includes mandatory statutory limitations disclaimers. |
| **Forensic ML Suite** | Offline scikit-learn statistical models: (1) **DVR Stream & Sector Classifier** identifying proprietary Dahua/Hikvision/TP-Link/H.264/Corrupt sectors by Shannon entropy and header signatures; (2) **Surveillance Activity Classifier** categorizing motion dynamics without biometric facial recognition. |
| **Multi-Camera Timeline** | Multi-camera chronological event correlation, non-destructive offset timestamp normalization (preserving raw timestamps), automated footage gap (>120s) and timeline reversal anomaly auditing. |
| **AI-Assisted Triage** | Triple-engine architecture: (1) **YOLOv8** (`ultralytics` + `yolov8n.pt`) deep neural network object detector for localized bounding-box surveillance triage; (2) **Google Gemini API** (`gemini-2.5-flash`) for cloud multimodal analysis; (3) **Offline Local ML Heuristic Classifier** (`ForensIQ-ML-Activity-Classifier-v1.0`) for air-gapped environments. Pre-classifies video frames for investigator review without biometric facial recognition. |
| **Court Dossier Reporting** | Interactive responsive HTML dossier (with dedicated `@media print` layout), structured JSON interchange dossier, and native A4 PDF generation with Section 65B IEA / Section 63 BSA certificates and cryptographic seals. |

---

## 📂 Project Structure

```
ForensIQ Vault/
├── forensiq/
│   ├── adapters/                  # Multi-vendor DVR decoders & capability registry
│   │   ├── base.py                # Abstract BaseAdapter & AdapterResponse
│   │   ├── dahua_export.py        # Dahua DHAV/.dav parser
│   │   ├── hikvision_export.py    # Hikvision HIK/.hkv parser
│   │   ├── tplink_onvif_rtsp.py   # TP-Link VIGI ONVIF parser
│   │   ├── generic_media.py       # Standard MP4/MKV/AVI ffprobe parser
│   │   ├── unknown_source.py      # Graceful fallback adapter
│   │   └── registry.py            # Adapter registry & profile synchronizer
│   ├── ml/                        # Offline Forensic Machine Learning Suite
│   │   ├── models/                # Serialized Joblib pipelines (StandardScaler + RandomForest)
│   │   ├── features.py            # Byte entropy & spatio-temporal feature extractors
│   │   ├── dvr_stream_classifier.py          # Sector & stream vendor classifier
│   │   ├── surveillance_activity_classifier.py # Ethical non-biometric activity classifier
│   │   └── EVALUATION_REPORT.md   # Model metrics, confusion matrices, F1-scores
│   ├── models/                    # 16 SQLAlchemy ORM forensic database models
│   ├── services/                  # Business logic services (Vault, Custody, Carving, Report, AI, etc.)
│   ├── templates/                 # Jinja2 HTML court dossier templates
│   ├── ui/                        # PySide6 desktop user interface
│   │   ├── pages/                 # 7 dedicated workspace pages
│   │   ├── widgets/               # Custom UI components (timeline scrubber, status badges, hex view)
│   │   └── theme.py               # Modern dark forensic stylesheet (QSS)
│   ├── utils/                     # Cryptographic hashing, canonical JSON, UTC formatting
│   ├── config.py                  # Environment and vault configuration
│   ├── constants.py               # Enums for forensic statuses and custody actions
│   ├── database.py                # SQLite session management & schema migrations
│   └── main.py                    # Application launch sequence
├── sample_evidence/               # Synthetic surveillance exhibits for live jury demonstration
├── scripts/
│   ├── generate_sample_evidence.py# Synthetic exhibit generator script
│   └── train_models.py            # ML training pipeline for forensic classifiers
├── tests/                         # Comprehensive pytest test suite (228 tests)
├── JURY_DEMO_SCRIPT.md            # 5-minute timed presentation walkthrough
├── pyproject.toml                 # Packaging & dependencies
└── README.md                      # Comprehensive documentation
```

---

## 🚀 Installation & Quickstart

### 1. Prerequisites
- **Python**: Version 3.11, 3.12, 3.13, or 3.14
- **Operating System**: Windows 10/11, Linux, or macOS

### 2. Clone Repository & Setup Virtual Environment
```powershell
git clone https://github.com/<your-repo>/forensiq-vault.git
cd "forensiq-vault"

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate
```

### 3. Install Dependencies
```powershell
pip install -e .
```

*(Optional) Configure Google Gemini API key for cloud-enhanced AI triage:*
```powershell
copy .env.example .env
# Edit .env and set GEMINI_API_KEY=your_key_here
```
*Note: If no API key is provided, ForensIQ Vault seamlessly runs its built-in local heuristic engine completely offline.*

---

## 🧪 Generating Demonstration Evidence & Running Tests

### Generate Synthetic Exhibits
To generate the four mock exhibits in `sample_evidence/`:
```powershell
python scripts/generate_sample_evidence.py
```
This generates:
1. `EX01_Dahua_CAM01_Entrance.dav` — Dahua CCTV capture with DHAV packet headers.
2. `EX02_Hikvision_CAM02_LoadingBay.hkv` — Hikvision capture with master signature and private tags.
3. `EX03_TPLink_CAM03_VIGI_ProfileS.mp4` — TP-Link VIGI ONVIF export container.
4. `EX04_Damaged_DVR_Carve_Target.raw` — Raw sector dump with corrupt partition headers followed by intact H.264 streams for video carving demonstrations.

### Train Forensic Machine Learning Models
To retrain the offline statistical classifiers (or view metrics in `forensiq/ml/EVALUATION_REPORT.md`):
```powershell
python scripts/train_models.py
```
This trains and validates two `Pipeline([StandardScaler, RandomForestClassifier])` models:
1. **DVR Stream & Sector Classifier**: Classifies disk sectors into `DAHUA_STREAM`, `HIKVISION_STREAM`, `TPLINK_ONVIF_STREAM`, `GENERIC_H264_STREAM`, and `CORRUPT_NOISE`.
2. **Surveillance Activity Classifier**: Classifies bounding box kinematics and pixel shifts into `person`, `vehicle`, `motion`, `scene_change`, and `anomaly` without facial recognition.

### Run Automated Test Suite
To verify the entire forensic pipeline (228 tests):
```powershell
pytest -v
```

---

## 🖥️ Launching the Application

Launch the desktop interface:
```powershell
python -m forensiq
```

### End-to-End Workflow in the UI:
1. **Case Management**: Click `New Case` and enter Case ID and Lead Investigator.
2. **Evidence Import**: Navigate to `Evidence Import`, select an exhibit from `sample_evidence/`. Watch streaming SHA-256 hashing and automatic read-only vault placement.
3. **Vendor Adapter Matrix**: Navigate to `Vendor Adapters`, observe auto-detection of Dahua/Hikvision signatures, and inspect the raw binary hex dump.
4. **Video Stream Carving**: Select `EX04_Damaged_DVR_Carve_Target.raw` in the Vendor Adapter page and click `Carve Video Stream`. The Annex-B scanner extracts intact H.264 NALUs and writes a verified derivative.
5. **Timeline & Normalization**: Correlate events across cameras, normalize clock offsets, and run AI preliminary triage.
6. **Cryptographic Chain of Custody**: View the tamper-proof ledger. Click `Verify Cryptographic Chain` to validate mathematical integrity.
7. **Forensic Report Generation**: Click `Generate Forensic Report` to export court-ready HTML, JSON, or PDF dossiers certified under Section 65B IEA / Section 63 BSA!

---

## ⚖️ Legal & Ethical Compliance

- **Indian Evidence Act, 1872 (Section 65B) & Bharatiya Sakshya Adhiniyam, 2023 (Section 63)**:
  Every generated report is cryptographically bound to the examining officer, software version, host operating environment, and digital evidence hashes.
- **Strict Prohibition on Biometric Facial Recognition**:
  In accordance with ethical AI governance and digital privacy standards, biometric facial recognition is prohibited. The tool assists investigators strictly with behavioral, temporal, and spatial anomaly triage.
- **Statutory Recovery Limitations Notice**:
  Recovery operations clearly disclose: *"Overwritten, encrypted, physically damaged, incomplete or heavily fragmented footage may be unrecoverable. Recovery outcomes must be validated against controlled ground truth where available."*

---

## 👥 Authors & Acknowledgments

- **Developer**: Solo Student Developer — Smart India Hackathon 2026
- **Problem Statement 26150**: National Technical Research Organisation (NTRO)
- **Theme**: Blockchain and Cybersecurity
