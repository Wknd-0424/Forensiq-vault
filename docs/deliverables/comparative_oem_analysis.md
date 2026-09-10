# Comparative OEM Surveillance Architecture & Format Analysis

**ForensIQ Vault — Technical Deliverable**  
**Event**: Smart India Hackathon 2026 (SIH 2026)  
**Problem Statement ID**: 26150  
**Target Organization**: National Technical Research Organisation (NTRO)  
**Theme**: Blockchain & Cybersecurity  

---

## Executive Summary

Digital Video Recorders (DVRs) and Network Video Recorders (NVRs) deployed across India originate from a heterogeneous set of global and domestic Original Equipment Manufacturers (OEMs). To date, forensic examiners investigating criminal incidents have been severely hindered by proprietary container formats, non-standard timestamp encodings, and vendor-specific disk partition schemes.

This technical deliverable provides a forensic comparative evaluation of all **8 named OEMs** identified in Smart India Hackathon Problem Statement 26150:
1. **Dahua Technology**
2. **Hikvision Digital Technology**
3. **CP Plus (Aditya Infotech Ltd)**
4. **Uniview Technologies (UNV)**
5. **Honeywell Security**
6. **TP-Link (VIGI / Tapo Surveillance)**
7. **Godrej Security Solutions**
8. **Matrix Comsec**

This document analyzes the proprietary container structures, byte-level header signatures, ONVIF conformance, timestamp encoding quirks, and the implementation tier within **ForensIQ Vault**.

---

## Comparative Analysis Matrix

| OEM Vendor | Primary Export Container(s) | Byte Signature / Magic Bytes | ONVIF Profile Conformance | Timestamp Encoding Characteristics | ForensIQ Vault Support Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dahua Technology** | `.dav`, `.mp4`, `.h264`, `.h265` | `DHAV` (0x44 0x48 0x41 0x56)<br>`DAHUA`<br>`DHFS` | Profile S, G, T | Binary-Coded Decimal (BCD) or 32-bit Unix epoch; timezone offsets frequently omitted from elementary headers. | **Full Container & Packet Parser** (`dahua_export.py`) |
| **Hikvision** | `.hkv`, `.mp4`, `.h264` | `HIKVISION` (9 bytes)<br>`HKAA`, `HKBB` | Profile S, G, T | Proprietary system header; millisecond packet tick counters; UTC timestamps in Big-Endian. | **Full Container & Packet Parser** (`hikvision_export.py`) |
| **CP Plus** | `.dav`, `.cvr`, `.mp4`, `.asf` | `CPPLUS` (0x43 0x50 0x50 0x4C 0x55 0x53)<br>`CPPL`<br>`CP PLUS` | Profile S, G (Orange / Indigo Series) | OEM firmware derivative of Dahua BCD formatting; high RTC clock drift in air-gapped deployments. | **Signature Detection & Container Parser** (`cpplus_export.py`) |
| **Uniview (UNV)** | `.uvf`, `.mp4`, `.ts` | `UBVR` (0x55 0x42 0x56 0x52)<br>`UNV\x00`<br>`UNVREC`<br>`unvh` | Profile S, G, T (EZStation / NVR) | GOP indexing tables embedded in file trailer or custom atom; timestamps recorded in UTC second offsets. | **Signature Detection & Container Parser** (`uniview_export.py`) |
| **Honeywell Security** | `.hos`, `.mp4`, `.asf` | `HONEYWELL`<br>`HOS\x01`, `HOS\x00`<br>`MAXPRO` | Profile S, G (Performance / MAXPRO Series) | Multiplexed metadata channels; timestamps synchronized to host controller; clip archives use packet tags. | **Signature Detection & Container Parser** (`honeywell_export.py`) |
| **TP-Link** | `.mp4`, `.mkv`, `.ts` | `ftypisom` / `ftypmp42`<br>`udta` atom naming `TP-Link VIGI` | Profile S, G (VIGI & Tapo lineups) | Standard ISO 14496-12 1904 epoch representation; UTC drift common if camera cannot reach internet NTP. | **Full Container & ONVIF Parser** (`tplink_onvif_rtsp.py`) |
| **Godrej Security** | `.gvr`, `.asf`, `.mp4`, `.avi` | `ASF` GUID / standard RIFF AVI headers with Godrej SeeThru tags | Profile S (on select enterprise IP models) | Embedded OSD text burn-in; internal RTC drift; fixed offset applied during USB thumb-drive export. | **Generic Media Fallback / Stream Carving** (`generic_media.py`) |
| **Matrix Comsec** | `.mat`, `.mp4`, `.avi` | Proprietary Matrix SATATYA clip header; RIFF AVI with private atoms | Profile S, G (SATATYA NVRs) | Millisecond timestamp offsets relative to camera stream initialization; relies on CMS sync. | **Generic Media Fallback / Stream Carving** (`generic_media.py`) |

---

## Detailed OEM Architectural Evaluations

### 1. Dahua Technology
- **Architecture**: Dahua DVRs utilize the proprietary **DHFS (Dahua File System)** on physical drives. DHFS uses a 512-byte sector architecture with 2 MB to 16 MB continuous cluster allocation.
- **Export Containers**: Standalone backups export into `.dav` containers. The stream is chunked into `DHAV` packets comprising channel ID, stream type (Main/Sub), timestamp, and payload length followed by raw Annex-B H.264/H.265 NAL units.
- **Forensic Challenges**: File carving from unallocated space requires identifying `DHAV` packet headers and continuous NAL reassembly because standard media players reject unfinalized `.dav` files.

### 2. Hikvision Digital Technology
- **Architecture**: Hikvision NVRs format storage into **HKFS**. System headers commence with the ASCII string `HIKVISION` followed by system header versions (`\x00\x01\x00\x02`).
- **Export Containers**: Video clips are exported into `.hkv` wrappers or wrapped MP4 files containing proprietary sub-packets (`HKAA` for video, `HKBB` for audio).
- **Forensic Challenges**: Timestamps are stored in binary header blocks. Truncated exports lack track-level index atoms (`moov`), requiring frame-by-frame Annex-B carving.

### 3. CP Plus (Aditya Infotech Ltd)
- **Architecture**: As India's market leader in commercial and residential surveillance, CP Plus DVRs ("Orange" and "Indigo" series) utilize firmware architectures derived from Dahua OEM platforms and custom Linux kernels.
- **Export Containers**: Primary exports use `.dav` or `.cvr` (CP Plus Video Record) containers, with packet headers containing `CPPLUS` or `CPPL` sync markers.
- **Forensic Challenges**: Standard media tools confuse CP Plus `.dav` files with standard Dahua files, misidentifying channel numbers and causing clock interpretation errors.

### 4. Uniview Technologies (UNV)
- **Architecture**: Uniview NVRs feature customized flash storage management and export video files with the `.uvf` (Uniview Video Format) extension.
- **Export Containers**: Headers begin with the 4-byte magic signature `UBVR` (0x55 0x42 0x56 0x52) or include `UNVREC` segment blocks. In MP4 container mode, Uniview embeds private metadata in the `unvh` box atom.
- **Forensic Challenges**: High-profile Ultra265 (HEVC with dynamic GOP smoothing) streams require accurate SPS/PPS extraction before rendering.

### 5. Honeywell Commercial Security
- **Architecture**: Honeywell MAXPRO NVR and Performance Series devices record continuous surveillance streams across enterprise networks.
- **Export Containers**: Forensic exports use the Honeywell Open Stream (`.hos`) format with magic bytes `HONEYWELL` and `HOS\x01`, or specialized ASF wrappers.
- **Forensic Challenges**: Multi-camera multiplexed backups interleave GOPs from multiple cameras into a single file, requiring forensic demultiplexing by camera identifier.

### 6. TP-Link (VIGI / Tapo Surveillance)
- **Architecture**: TP-Link VIGI enterprise and Tapo consumer security systems adhere closely to modern ONVIF standards.
- **Export Containers**: Encapsulated in standard ISO Base Media File Format (ISOBMFF / MP4) containers, storing vendor descriptors in `udta` boxes.
- **Forensic Challenges**: In air-gapped or CCTV-isolated LANs, internal RTC clocks frequently drift by several minutes to hours, requiring non-destructive timestamp offset normalization.

### 7. Godrej Security Solutions
- **Architecture**: Godrej SeeThru and domestic DVR series use standard Linux FAT32/ext4 partitions storing raw elementary H.264 streams or standard AVI/ASF files.
- **Forensic Quirks**: Video streams often have timestamps burned directly into the OSD pixels rather than preserved in digital container metadata tracks.
- **Support Strategy**: Processed cleanly via ForensIQ Vault's `GenericMediaAdapter` or Annex-B NAL unit stream carver when physical storage is damaged.

### 8. Matrix Comsec
- **Architecture**: Matrix SATATYA IP video surveillance solutions export via centralized CMS into proprietary or AVI/MP4 containers.
- **Forensic Quirks**: Relies heavily on external centralized NTP; when exported independently from thumb drives, raw streams lack metadata containers.
- **Support Strategy**: Processed via `GenericMediaAdapter` with automatic fallback to `UnknownSourceAdapter`.

---

## Standards & Research References

1. **ONVIF Core Specification v22.12**: Profiles S (Basic Video), G (Edge Storage and Retrieval), and T (Advanced Video Streaming).
2. **ISO/IEC 14496-10 / ITU-T H.264**: Advanced Video Coding for Generic Audiovisual Services (Annex B Byte Stream Format).
3. **ISO/IEC 14496-12**: ISO Base Media File Format (ISOBMFF).
4. **NIST SP 800-86**: *Guide to Integrating Forensic Techniques into Incident Response*.
5. **Bharatiya Sakshya Adhiniyam, 2023 (BSA)**: Section 63 (Admissibility of Electronic Records).
6. **Indian Evidence Act, 1872**: Section 65B (Special Provisions as to Evidence Relating to Electronic Record).
