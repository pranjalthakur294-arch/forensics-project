# Digital Forensics Suite — Demonstration Walkthrough & Visual Portfolio Guide

This document provides end-to-end forensic demonstration scenarios with verified CLI commands and actual terminal outputs, along with professional guidelines for capturing and embedding portfolio screenshots on GitHub.

---

## 1. End-to-End Module Demonstrations

### Demonstration 1: Crypto Lab — Tamper-Evident Evidence Preservation

#### Scenario:
An investigator has extracted confidential evidence from a seized drive (`test_secret.txt`). The file must be encrypted with AES-256-GCM using a password-derived key (PBKDF2-HMAC-SHA256), a custody evidence record must be generated with dual hashes and HMAC signing, and tamper detection must be demonstrated.

#### Step 1: Benchmark Host Hardware KDF Performance
```powershell
cd crypto_lab
py crypto_tool.py benchmark
```
**Actual Terminal Output:**
```
--- PBKDF2-HMAC-SHA256 Hardware Benchmark ---
  Iterations      | Duration (ms)   | Rate (iters/sec)
  ----------------------------------------------------
  100,000         | 59.71           | 1,674,644
  200,000         | 153.24          | 1,305,141
  600,000         | 363.42          | 1,650,985
  1,000,000       | 648.39          | 1,542,287
----------------------------------------------
```

#### Step 2: Encrypt with Version 2 Format & Generate Signed Custody Metadata
```powershell
$env:FORENSIC_KEY = "ForensicsPass2026!"
py crypto_tool.py encrypt test_secret.txt --password-env FORENSIC_KEY --hmac-key "LabCustodyKey#42" -f
```
**Actual Terminal Output:**
```
[+] Encryption Successful (Format Version 2)!
    Encrypted File:     test_secret.txt.enc
    Plaintext SHA-256:  4ba8bf21c572cbad71afbafa045c7f4615afa7b11bd3dab3972a1d628fc7b49c
    Ciphertext SHA-256: 440f5331a88c6e41e1e606d58b3373e81ecbe46817756fb812c8fe36a1da6d79
    Evidence Metadata:  test_secret.txt.enc.evidence.txt
```

#### Step 3: Inspect the Generated Evidence Custody Record
```powershell
Get-Content test_secret.txt.enc.evidence.txt
```
**Sample Contents:**
```
Evidence Custody Report
Generated: 2026-10-30T09:37:33Z
Evidence ID: a673d3fe-f63b-4573-8a90-eead5ef6f264
Target File: test_secret.txt.enc
Format Version: 2
Original File: test_secret.txt
File Size (bytes): 62
SHA-256 (Plaintext):  4ba8bf21c572cbad71afbafa045c7f4615afa7b11bd3dab3972a1d628fc7b49c
SHA-256 (Ciphertext): 440f5331a88c6e41e1e606d58b3373e81ecbe46817756fb812c8fe36a1da6d79
HMAC-SHA256 Authenticity: b5e4f208112c8427513df5d3d4b6842df1542f2b347b3dc6012423ff4d3a3cc1
```

#### Step 4: Verify Custody Integrity & Authenticity
```powershell
py crypto_tool.py verify test_secret.txt test_secret.txt.enc.evidence.txt --hmac-key "LabCustodyKey#42"
```
**Actual Terminal Output:**
```
[+] Integrity VERIFIED: Integrity and HMAC authenticity verified successfully.
```

#### Step 5: Decrypt and Authenticate Container
```powershell
py crypto_tool.py decrypt test_secret.txt.enc -o test_secret_recovered.txt --password-env FORENSIC_KEY -f
```
**Actual Terminal Output:**
```
[+] Decryption & Authentication Successful!
    Recovered File: test_secret_recovered.txt
    SHA-256: 4ba8bf21c572cbad71afbafa045c7f4615afa7b11bd3dab3972a1d628fc7b49c
```

---

### Demonstration 2: Disk Forensics — Reconstructing an NTFS Activity Timeline

#### Scenario:
An investigator receives two separate CSV reports extracted from an employee workstation:
1. `sample_mft.csv`: Extracted MFT entries showing file creations and modification timestamps.
2. `sample_recycle.csv`: Extracted `$I` Recycle Bin headers showing files deleted by the user.

The goal is to parse both artifacts, normalize all timestamps to UTC ISO-8601, evaluate deletion heuristics, and merge them into a chronological master timeline.

#### Step 1: Parse the MFT CSV Export
```powershell
cd ../disk_forensics
py mft_parser.py sample_mft.csv
```
**Actual Terminal Output:**
```
[INFO] Successfully parsed 4 records from sample_mft.csv
[INFO] Normalized MFT report written to: .\mft_report.csv
[INFO] MFT timeline written to: .\mft_timeline.csv
```

#### Step 2: Parse the Recycle Bin Artifact Export
```powershell
py recycle_parser.py sample_recycle.csv
```
**Actual Terminal Output:**
```
[INFO] Successfully parsed 3 Recycle Bin records from sample_recycle.csv
[INFO] Recycle Bin report written to: .\recycle_report.csv
[INFO] Recycle Bin timeline written to: .\recycle_timeline.csv
```

#### Step 3: Merge and Fuse Timelines Chronologically
```powershell
py merge_timelines.py mft_timeline.csv recycle_timeline.csv -o merged.csv
```
**Actual Terminal Output:**
```
[INFO] Loaded 12 events from mft_timeline.csv
[INFO] Loaded 3 events from recycle_timeline.csv
[INFO] Wrote 15 chronological events to: merged.csv
```

#### Step 4: Review the Unified Master Forensic Timeline
```powershell
Get-Content merged.csv | Select-Object -First 10
```
**Actual Chronological Output:**
```csv
timestamp,source_artifact,event,filename,record,size,fullpath,original_path,recycle_name,flags,deleted
2024-11-27 09:16:44,MFT,created,image.png,1001,204800,C:\Users\Admin\Pictures\image.png,,,InUse,False
2024-11-28 14:15:00,MFT,modified,image.png,1001,204800,C:\Users\Admin\Pictures\image.png,,,InUse,False
2024-11-29 20:44:10,RecycleBin,deleted,holiday.jpg,,153600,,C:\Users\Admin\Pictures,$R104.jpg,,
2024-12-01 11:05:31,MFT,created,secret.txt,1002,4096,C:\Users\Admin\Desktop\secret.txt,,,Deleted,True
2024-12-01 11:07:00,MFT,modified,secret.txt,1002,4096,C:\Users\Admin\Desktop\secret.txt,,,Deleted,True
2024-12-01 11:10:45,RecycleBin,deleted,secret.txt,,4096,,C:\Users\Admin\Desktop,$R103.txt,,
2024-12-02 08:30:12,MFT,created,report.docx,1003,51200,C:\Users\Admin\Documents\report.docx,,,InUse,False
2024-12-02 08:31:00,MFT,accessed,report.docx,1003,51200,C:\Users\Admin\Documents\report.docx,,,InUse,False
2024-12-03 16:50:22,RecycleBin,deleted,notes.txt,,1024,,C:\Users\Admin\Desktop,$R105.txt,,
```

---

### Demonstration 3: Network Forensics — PCAP Triage & DPI Extraction

#### Scenario:
A suspicious network capture (`test_capture.pcap`) was captured from an endpoint suspected of data staging. The analyst needs to determine top talkers, DNS query activity, and unencrypted TLS Server Name Indications (SNI).

#### Step 1: Rapid PCAP Triage
```powershell
cd ../network_forensics
py pcap_analyze.py test_capture.pcap
```
**Actual Terminal Output:**
```
[+] Loaded 20 packets from: test_capture.pcap

--- Protocol Distribution (20 packets) ---
  TCP     :    12 packets (60.0%)
  UDP     :     8 packets (40.0%)

--- Top 10 Communicating IP Addresses (IPv4 & IPv6) ---
  192.168.29.104                             ->   10 occurrences
  13.69.116.109                              ->   10 occurrences
  2405:201:5c09:1126:2c89:c8b9:92f3:b25f     ->   10 occurrences
  2405:201:5c09:1126::c0a8:1d01              ->    4 occurrences
  2404:6800:4002:802::200a                   ->    2 occurrences

--- Top 10 Ports (TCP/UDP) ---
  Port 443    ->   16 hits
  Port 50255  ->   10 hits
  Port 53     ->    4 hits

--- DNS Queries Identified (1 unique) ---
  Query: mobile.events.data.microsoft.com
```

#### Step 2: Extended Analysis with Timeline & SHA-256 Custody Hash
```powershell
py pcap_analyze_extended.py test_capture.pcap
```
**Actual Terminal Output:**
```
[+] Loaded 20 packets from: test_capture.pcap

--- Capture Overview ---
  Total Packets:   20
  First Packet:    2025-12-11 16:52:41
  Last Packet:     2025-12-11 16:52:46

--- Top Communicating Conversations (IP Pairs) ---
  13.69.116.109 <---> 192.168.29.104 : 10 packets
  2405:201:5c09:1126:2c89:c8b9:92f3:b25f <---> 2405:201:5c09:1126::c0a8:1d01 : 4 packets

[+] Timeline CSV written to: test_capture_timeline.csv
[+] Evidence file written to: test_capture.pcap.evidence.txt
    PCAP SHA-256: 6a06222888f7379b46d256d02aee66cf82e75c1b0a340dbf1f04f36eab047b78
```

#### Step 3: Run Full Repository Test Suite (34 Automated Tests)
```powershell
cd ..
py run_tests.py
```
**Actual Terminal Output:**
```
====================================================================
  DIGITAL FORENSICS SUITE — AUTOMATED VERIFICATION SUITE
====================================================================
Ran 34 tests in 3.177s

OK
====================================================================
Tests Run: 34 | Failures: 0 | Errors: 0
====================================================================
```

---

## 2. Professional Screenshot Capture Guide

To visually showcase these demonstrations on your GitHub repository or LinkedIn portfolio, follow these best practices:

### Recommended Terminal Settings
1. **Terminal Application:** Use **Windows Terminal** (or iTerm2 / Kitty on macOS/Linux).
2. **Font:** Use a clean monospace developer font such as **Cascadia Code**, **Fira Code**, or **JetBrains Mono**.
3. **Color Theme:** Use a high-contrast dark theme like **One Dark**, **Dracula**, or **Solarized Dark**.
4. **Window Dimensions:** Size the window to approximately 100 columns by 30 rows for optimal readability without horizontal scrolling.

### Recommended Screen Capture Methods
1. **Windows Snipping Tool (`Win + Shift + S`):**
   - Select "Window Snip" to capture the terminal window with clean rounded borders and drop shadow.
   - Save screenshots into a dedicated directory: `docs/screenshots/` (e.g. `crypto_demo.png`, `disk_timeline_demo.png`, `network_dpi_demo.png`, `tests_passing.png`).
2. **Carbon / Ray.so (for Code Snippets):**
   - For highlighting key code blocks (such as the AAD header binding logic or TCP stream reassembly), use [Carbon.now.sh](https://carbon.now.sh) or [Ray.so](https://ray.so) with 2x resolution and dark background.

### Embedding Images in Markdown
Once images are placed in `docs/screenshots/`:
```markdown
<div align="center">
  <img src="docs/screenshots/tests_passing.png" alt="34/34 Tests Passing" width="850">
  <p><em>Figure 1: Automated Verification Suite executing 34 unit & security tests.</em></p>
</div>
```
