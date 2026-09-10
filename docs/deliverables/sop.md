# Standard Operating Procedure (SOP): Digital Surveillance Video Forensics

**Document Reference**: FIQ-SOP-2026-V1  
**Target Organization**: Law Enforcement, Judicial Forensics Laboratories & NTRO  
**Tool**: ForensIQ Vault (v1.0.0)  
**Legal Framework**: Section 63, Bharatiya Sakshya Adhiniyam, 2023 (BSA) / Section 65B, Indian Evidence Act, 1872  

---

## 1. Purpose & Scope

This Standard Operating Procedure (SOP) specifies the exact, step-by-step procedural workflow required of digital forensic examiners conducting evidence acquisition, extraction, recovery, analysis, and court dossier compilation from seized CCTV Digital Video Recorders (DVRs), Network Video Recorders (NVRs), and export storage media using **ForensIQ Vault**.

Compliance with this SOP ensures that all digital exhibits satisfy statutory chain-of-custody, authenticity, and admissibility requirements before the High Courts and trial courts of India.

---

## 2. Core Forensic Invariants (Zero-Tolerance Rules)

1. **Rule 1 — Absolute Original Immutability**: Under no circumstances shall an original seized storage drive or exported file be opened, played, carved, or modified directly.
2. **Rule 2 — Immediate Read-Only Enforcement**: Original evidence imported into the vault is locked with operating system read-only attributes (`chmod 0444`).
3. **Rule 3 — Hash-Verified Working Copy Isolation**: All decoding, carving, ffprobe metadata extraction, and AI triage operate strictly on hash-verified working copies (`vault/.../working_copy/`).
4. **Rule 4 — Append-Only Hash-Chained Ledger**: Every action generates a canonical JSON SHA-256 custody event (`previous_event_hash -> event_hash`).
5. **Rule 5 — Segregated Derivatives**: Any recovered video or transcoded stream is placed into a segregated `derivatives/` directory, independently hashed, assigned an atomic `.manifest.json`, and linked to its parent exhibit.
6. **Rule 6 — No Invented Metadata**: If a proprietary DVR timestamp is missing or unparseable, it is marked `None` / `Unknown` with an explicit audit warning.
7. **Rule 7 — Strict Ethical AI Boundary**: AI triage is restricted strictly to object and activity classes (`person`, `vehicle`, `motion`, `scene_change`). **Biometric facial recognition, landmark feature extraction, and identity matching are prohibited by architecture.** All AI detections require human examiner confirmation (`status = PENDING`).

---

## 3. Step-by-Step Operating Procedure

### Step 1: On-Scene Seizure & Hardware Write-Blocking
1. Document the physical state, make, model, serial number, and power state of the DVR/NVR at the scene of crime.
2. If the DVR is powered on, photograph the live system clock display and compare with an accurate Indian Standard Time (IST) reference (GPS or NTP clock) to calculate baseline clock drift.
3. Power down the device safely (or pull the power plug if the system is actively overwriting footage).
4. Remove the internal hard disk drive(s) (SATA/IDE).
5. Attach the drive to a certified forensic hardware write-blocker (e.g., Tableau T8u Forensic USB 3.0 Bridge) before connecting to the forensic examination workstation.

### Step 2: Bit-Stream Forensic Acquisition (`imaging_service`)
1. Launch **ForensIQ Vault** on the analysis workstation:
   ```powershell
   python -m forensiq
   ```
2. Open or create the target case (`CASE_CREATED` custody event recorded).
3. Navigate to **Evidence Import** -> click the **Forensic Acquisition (.img)** tab.
4. Select the physical drive device node (or raw forensic dump file in simulated write-blocked mode for lab analysis).
5. Verify that **Simulated Write-Blocked Acquisition** is active.
6. Set the block read size to `64 KB (65,536 bytes) — Forensic Standard`.
7. Enter the forensic examiner's name and exhibit number (e.g., `EX-HDD-01`).
8. Click **Acquire Forensic Bit-Stream Image (.img)**:
   - The acquisition engine reads the source sequentially block-by-block.
   - Dual cryptographic hashes (SHA-256 and MD5) are computed simultaneously as chunks are written into `vault/{case_id}/evidence/{evidence_id}/original/`.
   - On completion, the engine performs an independent read-back pass, re-reading the entire `.img` file from disk to verify byte-level equality.
   - Operating system read-only permissions (`chmod 0444`) are locked.
   - The atomic companion manifest `imaging_manifest.json` is generated.
   - Custody events `IMAGE_CREATED` and `IMAGE_VERIFIED` are committed to the cryptographic ledger.
   - An exact working copy is generated in `vault/.../working_copy/`.

### Step 3: Direct File Ingestion (For Exported Evidence)
*If surveillance footage was obtained as pre-exported files (e.g., `.dav`, `.hkv`, `.mp4` on USB drives):*
1. In the **Evidence Import** page, select the **File Ingestion** tab.
2. Browse to the evidence file and verify the file extension and size.
3. Enter the evidence exhibit number and examiner name.
4. Click **Import Evidence File**:
   - The file is validated and streaming dual-hashed (SHA-256 + MD5).
   - Stored read-only in `vault/.../original/`.
   - Verified working copy created in `vault/.../working_copy/`.
   - Manifest generated and `EVIDENCE_IMPORTED` logged to custody ledger.

### Step 4: Automated Vendor Adapter Identification
1. Navigate to **Adapter Capabilities & Carving**.
2. Select the evidence exhibit from the active case list.
3. The **AdapterRegistry** inspects the file header byte signatures:
   - **Dahua**: Matches `DHAV`, `DAHUA`, or `DHFS` superblock.
   - **Hikvision**: Matches `HIKVISION` or `HKAA`/`HKBB` packet tags.
   - **CP Plus**: Matches `CPPLUS`, `CPPL`, or `.cvr` containers.
   - **Uniview**: Matches `UBVR`, `UNV\x00`, `UNVREC`, or `unvh` box.
   - **Honeywell**: Matches `HONEYWELL`, `HOS\x01`, or `MAXPRO` headers.
   - **TP-Link**: Matches ONVIF Profile S container markers.
   - **Fallback**: Dispatches to `GenericMediaAdapter` or `UnknownSourceAdapter`.
4. Inspect the **Multi-Vendor Profile Matrix** to review supported features and vendor-specific limitations.

### Step 5: Video Metadata Analysis & Timestamp Normalization
1. Navigate to **Video Metadata** page.
2. Review the four-part forensic validation check:
   - Stream container & codec consistency.
   - Future/past timestamp sanity.
   - Bitrate & truncation verification.
   - Video geometry (resolution, framerate, aspect ratio).
3. If camera clock drift was observed in Step 1:
   - Navigate to **Timeline & AI Triage**.
   - Input the measured clock offset (e.g., `+120.0s`) and document the justification (e.g., *"DVR internal RTC was 2m 00s behind Indian Standard Time"*).
   - Click **Apply Normalization**.
   - The normalized UTC timeline updates immediately; the raw original camera timestamp remains unedited.
   - Custody event `TIMESTAMP_NORMALIZATION_APPLIED` is recorded in the ledger.

### Step 6: Two-Tier Deleted & Damaged Footage Recovery
*If the surveillance media is corrupted, partially overwritten, or unallocated:*
1. Navigate to **Adapter Capabilities & Carving**.
2. Review the **Forensic Hex Dump** and sector byte entropy.
3. The system executes a two-tier recovery workflow:
   - **Tier 1 (Filesystem Index Recovery)**: Scans for proprietary partition tables (e.g., Dahua DHFS deleted cluster entries) to recover complete continuous recording sessions with channel and timestamp metadata intact.
   - **Tier 2 (Deep Annex-B NAL Stream Carving)**: If filesystem structures are unallocated or destroyed, falls back to deep byte-level scanning for H.264/H.265 SPS (Sequence Parameter Set), PPS, and IDR keyframe start codes (`0x000001`/`0x00000001`).
4. Click **Carve Video Stream**:
   - Reconstructed stream is written into `vault/.../derivatives/`.
   - Derivative is independently hashed (SHA-256) and sealed with companion manifest.
   - Custody events `RECOVERY_ATTEMPTED` and `DERIVATIVE_CREATED` are logged.

### Step 7: Ethical AI Triage & Analyst Verification
1. In the **Timeline & AI Triage** page, select the working copy or carved derivative.
2. Execute AI Video Triage (YOLOv8 / Local Forensic Activity Classifier).
3. Verify that the **Biometric Facial Recognition Prohibited** guard is active.
4. Review detected candidates (`person`, `vehicle`, `motion`, `scene_change`).
5. For each candidate finding:
   - Review the bounding box and keyframe image.
   - Click **Confirm Finding** (or **Reject Finding**).
   - Enter human forensic examiner remarks (e.g., *"Confirmed suspect vehicle entering loading bay at 10:32:15 UTC"*).
   - Status updates from `PENDING` to `CONFIRMED`.
   - Custody event `DETECTION_REVIEWED` is logged.

### Step 8: Cryptographic Ledger Verification & Dossier Compilation
1. Navigate to **Chain of Custody & Reports**.
2. Click **Verify Cryptographic Chain**:
   - The verification engine computes canonical SHA-256 hashes across every event block from the genesis block (`CASE_CREATED`) to the final action.
   - Confirms that `previous_event_hash` matches throughout.
   - Displays verification badge: `✔ CHAIN INTACT (Cryptographic Audit Verified)`.
3. In the **Report Generation** panel, select format:
   - **Interactive HTML Report Dossier** (for digital review and print layout).
   - **Structured JSON Manifest** (for inter-agency data interchange).
   - **Native A4 PDF Report** (for physical submission to the court).
4. Verify that the compiled report includes:
   - Complete exhibit metadata and dual hashes.
   - Full timeline with raw and normalized timestamps.
   - All confirmed AI detections with examiner notes.
   - The mathematical chain of custody audit trail.
   - The statutory certificate under **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023** and **Section 65B of the Indian Evidence Act, 1872**.
5. Seal the exported dossier and submit into legal evidence custody.
