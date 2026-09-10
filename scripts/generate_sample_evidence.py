"""
scripts/generate_sample_evidence.py
------------------------------------
Forensic synthetic evidence generator for ForensIQ Vault jury demonstrations.

Generates realistic mock surveillance exhibits in `sample_evidence/`:
  1. EX01_Dahua_CAM01_Entrance.dav         - Dahua DHAV proprietary stream with H.264 NALUs.
  2. EX02_Hikvision_CAM02_LoadingBay.hkv   - Hikvision container with HKAA packet header and H.264 stream.
  3. EX03_TPLink_CAM03_VIGI_ProfileS.mp4  - TP-Link VIGI ONVIF export container.
  4. EX04_Damaged_DVR_Carve_Target.raw     - Corrupted filesystem sector noise prefix + intact Annex-B H.264 stream for live carving demonstration.

Usage:
    python scripts/generate_sample_evidence.py
"""

import os
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_evidence"


def build_annex_b_h264_stream(num_frames: int = 15) -> bytes:
    """Build a synthetic valid Annex-B H.264 byte stream."""
    # SPS (Sequence Parameter Set) - Baseline Profile, Level 3.1
    sps = b"\x00\x00\x00\x01\x67\x42\x00\x1f\xda\x01\x40\x16\xe8\x80"
    # PPS (Picture Parameter Set)
    pps = b"\x00\x00\x00\x01\x68\xce\x3c\x80"
    # IDR Keyframe (Instantaneous Decoder Refresh)
    idr = b"\x00\x00\x00\x01\x65\x88\x84\x00\x10\xff\x20\x33\x44\x55\x66\x77\x88"

    stream = bytearray(sps + pps + idr)

    # Subsequent predicted slices (Non-IDR)
    for i in range(1, num_frames):
        # 3-byte start code + type 1 (slice)
        slice_payload = bytes([i % 256, (i * 7) % 256, (i * 13) % 256, 0xAA, 0xBB])
        slice_nalu = b"\x00\x00\x01\x41\x9a" + slice_payload
        stream.extend(slice_nalu)

    return bytes(stream)


def generate_dahua_dav(output_path: Path) -> None:
    """Create a realistic Dahua .dav file with DHAV header and H.264 stream."""
    dhav_header = (
        b"DHAV"                                # Magic bytes
        b"\x01\x00"                            # Channel 1
        b"\x00\x00"                            # Stream type: Main
        b"\x20\x26\x09\x06\x10\x30\x00\x00"    # Timestamp: 2026-09-06 10:30:00
        b"\x00\x10\x00\x00"                    # Payload length
    )
    video_stream = build_annex_b_h264_stream(num_frames=20)
    data = dhav_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created Dahua exhibit: {output_path.name} ({len(data)} bytes)")


def generate_hikvision_hkv(output_path: Path) -> None:
    """Create a realistic Hikvision .hkv file with HIKVISION master header."""
    hik_header = (
        b"HIKVISION"                           # Magic bytes (9 bytes)
        b"\x00\x01\x00\x02"                    # System header version
        b"HKAA"                                # Private packet tag
        b"\x00\x02"                            # Channel 2
        b"\x20\x26\x09\x06\x10\x31\x15\x00"    # Timestamp: 2026-09-06 10:31:15
    )
    video_stream = build_annex_b_h264_stream(num_frames=18)
    data = hik_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created Hikvision exhibit: {output_path.name} ({len(data)} bytes)")


def generate_tplink_vigi_mp4(output_path: Path) -> None:
    """Create a realistic TP-Link VIGI ONVIF export MP4 container."""
    # Standard ISO MP4 container box header: ftypisom
    ftyp_box = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2avc1mp41"
    # Custom vendor comment/udta box embedding TP-Link VIGI profile metadata
    vigi_metadata = b"\x00\x00\x00\x30udta\x00\x00\x00\x28nameTP-Link VIGI C340 ONVIF Profile S"
    video_stream = build_annex_b_h264_stream(num_frames=24)
    # mdat box
    mdat_header = (len(video_stream) + 8).to_bytes(4, byteorder="big") + b"mdat"

    data = ftyp_box + vigi_metadata + mdat_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created TP-Link exhibit: {output_path.name} ({len(data)} bytes)")


def generate_cpplus_dav(output_path: Path) -> None:
    """Create a realistic CP Plus .dav exhibit with CPPLUS/CPPL headers and H.264 stream."""
    cpplus_header = (
        b"CPPLUS"                              # Magic bytes
        b"\x04\x00"                            # Channel 4
        b"\x00\x00"                            # Stream type: Main
        b"\x20\x26\x09\x06\x10\x32\x00\x00"    # Timestamp: 2026-09-06 10:32:00
        b"CPPL"                                # CP Plus packet sync tag
        b"\x00\x10\x00\x00"                    # Payload length
    )
    video_stream = build_annex_b_h264_stream(num_frames=20)
    data = cpplus_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created CP Plus exhibit: {output_path.name} ({len(data)} bytes)")


def generate_uniview_uvf(output_path: Path) -> None:
    """Create a realistic Uniview .uvf exhibit with UBVR and UNVREC headers."""
    unv_header = (
        b"UBVR"                                # Magic bytes
        b"\x00\x01\x00\x01"                    # Format version
        b"UNVREC"                              # Uniview recording tag
        b"\x05\x00"                            # Channel 5
        b"\x20\x26\x09\x06\x10\x33\x00\x00"    # Timestamp: 2026-09-06 10:33:00
        b"\x00\x12\x00\x00"                    # Block size
    )
    video_stream = build_annex_b_h264_stream(num_frames=18)
    data = unv_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created Uniview exhibit: {output_path.name} ({len(data)} bytes)")


def generate_honeywell_hos(output_path: Path) -> None:
    """Create a realistic Honeywell .hos exhibit with HONEYWELL/HOS headers."""
    honeywell_header = (
        b"HONEYWELL"                           # Master magic bytes (9 bytes)
        b"HOS\x01"                             # Honeywell Open Stream header
        b"MAXPRO"                              # MAXPRO clip marker
        b"\x06\x00"                            # Channel 6
        b"\x20\x26\x09\x06\x10\x34\x00\x00"    # Timestamp: 2026-09-06 10:34:00
    )
    video_stream = build_annex_b_h264_stream(num_frames=22)
    data = honeywell_header + video_stream
    output_path.write_bytes(data)
    print(f"  [+] Created Honeywell exhibit: {output_path.name} ({len(data)} bytes)")


def generate_corrupted_carve_target(output_path: Path) -> None:
    """Create a corrupted DVR raw disk dump with salvageable Annex-B H.264 streams."""
    # Corrupt sector noise simulating wiped/damaged partition tables and bad sectors
    noise_prefix = os.urandom(1024 * 4)  # 4 KB of corrupted raw sectors
    # Embedded intact H.264 Annex-B stream
    intact_h264 = build_annex_b_h264_stream(num_frames=30)
    # Corrupt trailing sector padding
    noise_suffix = os.urandom(512)

    data = noise_prefix + intact_h264 + noise_suffix
    output_path.write_bytes(data)
    print(f"  [+] Created Corrupted Carve Target: {output_path.name} ({len(data)} bytes)")


def generate_readme(output_dir: Path) -> None:
    """Generate explanatory README for the sample evidence directory."""
    readme_content = """# ForensIQ Vault - Sample Demonstration Exhibits

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

### 5. `EX05_CPPlus_CAM04_Perimeter.dav`
- **Vendor / Format**: CP Plus (`.dav` container with `CPPLUS` / `CPPL` headers).
- **Camera Location**: Camera 04 (Perimeter Fence).
- **Test Use Case**: Demonstrates CP Plus proprietary signature recognition and Orange/Indigo series surveillance export support.

### 6. `EX06_Uniview_CAM05_ServerRoom.uvf`
- **Vendor / Format**: Uniview Technologies (`.uvf` container with `UBVR` / `UNVREC` signatures).
- **Camera Location**: Camera 05 (Server Room).
- **Test Use Case**: Demonstrates Uniview UNV surveillance export identification and UVF container parsing.

### 7. `EX07_Honeywell_CAM06_HQGate.hos`
- **Vendor / Format**: Honeywell Security (`.hos` container with `HONEYWELL` / `HOS` / `MAXPRO` headers).
- **Camera Location**: Camera 06 (HQ Main Gate).
- **Test Use Case**: Demonstrates Honeywell MAXPRO / Performance Series NVR video clip detection.

---

## Forensic Invariant Note
All imported evidence files are copied into the secure `vault/` directory and permanently locked read-only (`chmod 0444`). All carving, analysis, and AI triage operate strictly on verified working copies.
"""
    (output_dir / "README.md").write_text(readme_content, encoding="utf-8")
    print(f"  [+] Created Documentation: {output_dir / 'README.md'}")


def main() -> None:
    print("\n=======================================================")
    print("ForensIQ Vault - Generating Sample Demonstration Exhibits")
    print("=======================================================\n")

    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    generate_dahua_dav(SAMPLE_DIR / "EX01_Dahua_CAM01_Entrance.dav")
    generate_hikvision_hkv(SAMPLE_DIR / "EX02_Hikvision_CAM02_LoadingBay.hkv")
    generate_tplink_vigi_mp4(SAMPLE_DIR / "EX03_TPLink_CAM03_VIGI_ProfileS.mp4")
    generate_corrupted_carve_target(SAMPLE_DIR / "EX04_Damaged_DVR_Carve_Target.raw")
    generate_cpplus_dav(SAMPLE_DIR / "EX05_CPPlus_CAM04_Perimeter.dav")
    generate_uniview_uvf(SAMPLE_DIR / "EX06_Uniview_CAM05_ServerRoom.uvf")
    generate_honeywell_hos(SAMPLE_DIR / "EX07_Honeywell_CAM06_HQGate.hos")
    generate_readme(SAMPLE_DIR)

    print("\n[OK] All sample exhibits generated in: sample_evidence/\n")


if __name__ == "__main__":
    main()

