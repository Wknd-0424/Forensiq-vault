# ForensIQ Vault — 5-Minute SIH 2026 Jury Demonstration Script ⏱️

**Smart India Hackathon 2026**  
**Problem Statement ID**: 26150  
**Organization**: National Technical Research Organisation (NTRO)  
**Theme**: Blockchain and Cybersecurity  
**Category**: Software  

---

## 🎯 Demonstration Objective
Demonstrate to the evaluators and technical jury that **ForensIQ Vault** solves the real-world operational challenges of DVR/NVR surveillance forensics while strictly preserving the chain of custody, ensuring Section 65B / Section 63 statutory admissibility, recovering damaged footage, and providing ethical AI triage without violating privacy norms.

---

## 🕒 Timed Demonstration Walkthrough (5 Minutes)

```
[0:00 - 0:45] ── The Core Forensic Problem & Architectural Invariants
[0:45 - 1:45] ── Evidence Ingestion, Streaming Hashing & Read-Only Vaulting
[1:45 - 2:45] ── Multi-Vendor Decoders & Live Video Carving of Damaged DVR Media
[2:45 - 3:45] ── Multi-Camera Clock Normalization & Ethical AI Triage
[3:45 - 4:30] ── Cryptographic Chain of Custody & Tamper Detection
[4:30 - 5:00] ── Court-Admissible Section 65B IEA / Sec 63 BSA Report Dossier
```

---

### Phase 1: The Core Forensic Problem & Invariants (0:00 - 0:45)
**Spoken Dialogue**:
> *"Respected Judges, digital video recorders seized from crime scenes are notoriously difficult to analyze. CCTV vendors like Dahua and Hikvision use proprietary containers and custom packet headers. Crucially, in many court cases, evidence is thrown out because an investigator opened the original file, altering timestamps and spoiling the digital exhibit.*
> 
> *ForensIQ Vault enforces a zero-trust forensic rule: **The original evidence is locked read-only in the vault and is NEVER modified, decoded, or carved directly.** All actions happen on hash-verified working copies."*

**Action on Screen**:
1. Launch app with `python -m forensiq`.
2. Point out the dark forensic theme and top header indicating case status and cryptographic integrity.
3. Click **New Case**, enter:
   - Case Number: `SIH-2026-NTRO-001`
   - Case Title: `Operation CyberShield Surveillance Audit`
   - Investigator: `Forensic Examiner Sharma`
   - Authority: `NTRO Digital Forensics Wing`
4. Click **Create Case**. Notice the `CASE_CREATED` block is instantly added to the ledger.

---

### Phase 2: Seizure Forensic Imaging & File Ingestion (0:45 - 1:45)
**Spoken Dialogue**:
> *"Most tools start after files are exported from a DVR. ForensIQ Vault starts at the moment of physical seizure.
> 
> Watch our **Forensic Bit-Stream Acquisition** engine in action: with write-block protection active, it reads the raw storage device sequentially in fixed blocks, streaming dual SHA-256 and MD5 hashes in real-time. On completion, it performs an independent read-back verification pass, writes a cryptographically sealed `imaging_manifest.json`, locks the original `.img` read-only (`chmod 0444`), and commits `IMAGE_CREATED` and `IMAGE_VERIFIED` to the immutable custody chain.
> 
> We can also ingest pre-exported files with identical cryptographic rigor."*

**Action on Screen**:
1. Navigate to **Evidence Import** page.
2. Click the **Forensic Acquisition (.img)** tab.
3. Click **Load EX04 Demo Dump** (`sample_evidence/EX04_Damaged_DVR_Carve_Target.raw`).
4. Point out the active **Simulated Write-Blocked Protection** invariant and block size selector (64 KB).
5. Click **Acquire Forensic Bit-Stream Image (.img)**.
6. Observe the live dual progress bar, the real-time acquisition console computing SHA-256 + MD5, passing independent read-back verification, locking read-only attributes, and writing the companion manifest.
7. Show the newly acquired `.img` exhibit appearing in the active case evidence list with its verified working copy.

---

### Phase 3: Multi-Vendor Decoders (6 OEMs) & Live Video Carving (1:45 - 2:45)
**Spoken Dialogue**:
> *"CCTV vendors use proprietary packet structures and containers. ForensIQ Vault provides modular adapter profiles covering 6 major OEMs: **Dahua, Hikvision, CP Plus, Uniview, Honeywell Security, and TP-Link VIGI/Tapo**.
> 
> What if the DVR file system was wiped or physically corrupted by water or power failure? Standard media players crash. Let me demonstrate our two-tier recovery engine: first scanning proprietary filesystem indices (like Dahua DHFS), and falling back to low-level Annex-B NAL unit carving."*

**Action on Screen**:
1. Navigate to **Adapter Capabilities & Carving** page.
2. Show the **Multi-Vendor Profile Matrix** listing Dahua, Hikvision, CP Plus, Uniview, Honeywell, and TP-Link.
3. Select `EX04_Damaged_DVR_Carve_Target.raw`.
4. Show the **Forensic Hex Dump** displaying wiped partition headers.
5. Click **Carve Video Stream**.
6. Watch the carver scan byte streams, locate Annex-B start codes (`0x000001`/`0x00000001`), extract H.264 SPS, PPS, and IDR keyframes, and reassemble an intact, playable `.h264` derivative in the segregated vault folder with cryptographic manifests!
7. Point out the statutory recovery disclaimer and the new `DERIVATIVE_CREATED` custody event.

---

### Phase 4: Multi-Camera Timeline Normalization & Ethical AI Triage (2:45 - 3:45)
**Spoken Dialogue**:
> *"In multi-camera investigations, individual camera clocks drift. If Camera 1 is 2 minutes behind real time, cross-camera chronology is corrupted. ForensIQ Vault preserves the raw camera timestamp forever, but calculates a normalized UTC timeline.
> 
> Now, regarding AI: Problem Statement 26150 mentions 'face, object, and motion detection'. We want to highlight a deliberate, principled engineering and legal decision:
> 
> **ForensIQ Vault strictly excludes biometric facial recognition and identity matching by architectural design.**
> 
> Under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA) and Section 65B of the Indian Evidence Act, probabilistic biometric matches without certified ground-truth templates create high risks of false positives and evidence suppression in court. Furthermore, under India's DPDP Act 2023 and the Puttaswamy privacy judgment, unconstrained biometric processing of bystander CCTV is legally hazardous.
> 
> We therefore restrict AI triage strictly to object categories—vehicles, person silhouettes, motion dynamics, and opt-in anonymized presence counts—with zero biometric templates. Crucially, every AI detection is initialized to PENDING and requires human forensic examiner confirmation."*

**Action on Screen**:
1. Navigate to **Timeline & AI Triage** page.
2. Select the exhibit and show the interactive custom timeline widget.
3. Apply a `+120.0s` offset adjustment with reason: `"DVR clock drift relative to NTP reference"`.
4. Show the timeline instantly updating while keeping raw device time untouched.
5. Review an AI candidate detection (`vehicle`), click **Confirm Finding**, and type analyst notes.
6. Show the ethical AI compliance badge confirming zero biometric template extraction.

---

### Phase 5: Cryptographic Chain of Custody & Tamper Detection (3:45 - 4:30)
**Spoken Dialogue**:
> *"How do we prove in court that no evidence or log was altered? Every single event—from case creation, evidence import, normalization, to carving—is mathematically chained using SHA-256 canonical JSON.*
> 
> *Each block stores the exact cryptographic hash of the previous block. Let's run a chain verification."*

**Action on Screen**:
1. Navigate to **Chain of Custody & Reports** page.
2. Show the sequential ledger with previous link and event hashes.
3. Click **Verify Cryptographic Chain**.
4. Show the glowing emerald badge: `✔ CHAIN INTACT (Cryptographic Audit Verified)`.
5. Point out that if any record in the database is modified externally, the chain verification detects the exact broken block immediately!

---

### Phase 6: Court-Admissible Dossier Generation (4:30 - 5:00)
**Spoken Dialogue**:
> *"Finally, an investigation is only as good as its court presentation. ForensIQ Vault generates court-admissible dossiers in HTML, JSON, and native A4 PDF.*
> 
> *Crucially for Indian legal proceedings, it automatically generates a legal certificate complying with **Section 65B of the Indian Evidence Act, 1872** and **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023**, complete with software hash seals, examiner signature blocks, and companion manifests."*

**Action on Screen**:
1. Click **📜 Generate Forensic Report**.
2. Select `HTML` or `PDF`. Enter certifying officer: `Forensic Examiner Sharma`.
3. Click **Generate Report**.
4. Click **Open Report** to reveal the dossier in browser or PDF viewer.
5. Highlight:
   - Executive Summary
   - Evidence Inventory with SHA-256 hashes
   - Forensic Sanity Validation Results
   - Reconstructed Chronological Timeline
   - Confirmed AI Findings with Disclaimers
   - Complete Cryptographic Custody Ledger
   - Formal Section 65B / Section 63 Legal Certificate.

---

## 🛡️ Key Defense Points for Jury Questions

### Q1: "Why don't you use Facial Recognition in your AI pipeline?"
**Answer**:
> *"Biometric facial recognition on low-resolution CCTV introduces unacceptable false-positive rates and significant privacy/legal concerns. Modern forensic best practices and NTRO guidelines require objective, non-biometric activity triage (person silhouette, vehicle classification, motion vectors, scene transitions). ForensIQ Vault strictly enforces this ethical constraint, ensuring high court admissibility while saving investigators hundreds of hours of manual scrubbing."*

### Q2: "What if the raw footage is heavily fragmented across non-contiguous sectors?"
**Answer**:
> *"Our carving engine uses an Annex-B NAL unit parser. It scans for both 3-byte (`0x000001`) and 4-byte (`0x00000001`) start codes, extracts Sequence Parameter Sets (SPS) and Picture Parameter Sets (PPS), and stitches together valid GOP (Group of Pictures) starting from IDR keyframes. Even when the file system table is completely lost, all intact video chunks are recovered into a segregated derivative with clear confidence ratings and statutory limitation warnings."*

### Q3: "How does your cryptographic custody ledger differ from a standard database log?"
**Answer**:
> *"A standard SQL database log can be updated, deleted, or altered using standard SQL queries without any indication of tampering. ForensIQ Vault structures every event into canonical JSON, incorporates the SHA-256 hash of the preceding event, and computes a unique cryptographic hash for that block. Any change to timestamps, actor IDs, or notes causes a hash mismatch that breaks the entire chain, which our verification engine flags immediately."*

### Q4: "How do you ensure Section 65B / Section 63 compliance?"
**Answer**:
> *"Under Section 65B of the Indian Evidence Act (and Section 63 of BSA 2023), electronic records must be accompanied by a certificate signed by a person occupying an official position responsible for the management of the relevant device, certifying that the computer operated properly and that the integrity of the data was uncompromised. ForensIQ Vault generates this certificate automatically, tying it directly to the examining officer, tool version, host operating environment, and immutable evidence SHA-256 digests."*
