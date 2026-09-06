# ForensIQ Vault - Sample Demonstration Exhibits

These synthetic evidence files are prepared for testing and live demonstration of the **ForensIQ Vault** forensic analysis platform (SIH 2026, Problem 26150 - NTRO).

---

## Exhibit Inventory

### 1. `EX01_Dahua_CAM01_Entrance.dav`
- **Vendor / Format**: Dahua Technology (`.dav` container with proprietary `DHAV` packet headers).
- **Camera Location**: Camera 01 (Entrance Gate).
- **Test Use Case**: Demonstrates proprietary Dahua adapter auto-detection, DHAV header inspection, and stream extraction.

### 2. `EX02_Hikvision_CAM02_LoadingBay.hkv`
- **Vendor / Format**: Hikvision (`.hkv` format with `HIKVISION` master magic bytes and `HKAA` packet metadata).
- **Camera Location**: Camera 02 (Loading Bay).
- **Test Use Case**: Demonstrates Hikvision vendor profile parsing, private tag recognition, and working copy generation.

### 3. `EX03_TPLink_CAM03_VIGI_ProfileS.mp4`
- **Vendor / Format**: TP-Link VIGI / Tapo Surveillance (`.mp4` container with ONVIF Profile S metadata).
- **Camera Location**: Camera 03 (Parking Lot).
- **Test Use Case**: Demonstrates IP camera ONVIF stream metadata decoding and timestamp normalization.

### 4. `EX04_Damaged_DVR_Carve_Target.raw`
- **Format**: Corrupted Raw Sector Dump (`.raw`).
- **Simulated Forensic Scenario**: DVR disk partition wiped or file system metadata corrupted. Standard media players fail to open this file.
- **Test Use Case**: 
  1. Open **Adapter Capabilities & Carving** page.
  2. Select this exhibit to observe the Hex Dump with corrupted headers.
  3. Click **Carve Video Stream**.
  4. The Annex-B NAL unit carver scans the stream, identifies SPS, PPS, IDR keyframes, and slices, and reassembles a clean `.h264` derivative in the segregated vault folder with cryptographic manifests!

---

## Forensic Invariant Note
All imported evidence files are copied into the secure `vault/` directory and permanently locked read-only (`chmod 0444`). All carving, analysis, and AI triage operate strictly on verified working copies.
