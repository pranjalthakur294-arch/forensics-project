# Digital Forensics Portfolio — Technical Interview Guide & Engineering Defense

This document provides a comprehensive technical defense of the **Forensics** repository, detailing the real-world cybersecurity problems solved, architectural decisions, technical challenges, security considerations, and **30 forensic interview questions with expert answers** across all three modules.

---

## 1. Executive Summary & Problems Solved

| Module | Real-World Cybersecurity Problem Solved |
| :--- | :--- |
| **Crypto Lab** | In forensic casework, seized evidence must be transferred or stored securely. Standard encryption without integrity verification leaves evidence vulnerable to bit-flipping attacks, tampering, or silent truncation. `crypto_tool.py` guarantees tamper-evident storage using AES-256-GCM with Additional Authenticated Data (AAD) header binding and non-repudiation tracking. |
| **Disk Forensics** | File deletions, staging, and exfiltration are often obfuscated across different Windows artifacts. MFT entries show modification/creation but lose original paths upon deletion; Recycle Bin `$I` records show deletion paths and timestamps but lack complete cluster history. This toolset correlates both artifacts into a unified chronological master timeline with deletion heuristic analysis. |
| **Network Forensics** | During network intrusion triage, analysts need rapid answers regarding which internal systems communicated with suspicious external IPs, what domains were queried, and what services were accessed. With modern traffic predominantly encrypted under TLS, `network_forensics` performs stateful stream reassembly to extract TLS Server Name Indications (SNI) and DNS queries without needing private decryption keys. |

---

## 2. Technology Selection Rationale

- **Python 3.10+ Standard Library + Minimal Dependencies:** Keeps forensic triage tools lightweight, portable, and easily auditable in forensic environments where deploying heavyweight appliances is impractical or legally constrained.
- **`pycryptodome` (AES-GCM & PBKDF2):** Selected over generic OpenSSL wrappers for fine-grained control over streaming AEAD updates, AAD binding, and direct authentication tag verification.
- **CSV-First Approach for Disk Triage:** Upstream commercial and open-source tools (Autopsy, FTK Imager, MFTECmd) export MFT and Recycle Bin records to CSV. Parsing CSVs allows cross-platform ingestion without requiring direct physical access to raw NTFS volume handles or OS kernel locks.
- **`scapy` & `pyshark` Dual-Engine Architecture:** Scapy provides zero-dependency, pure-Python packet inspection and stateful stream reassembly, while PyShark harnesses TShark’s mature C-based protocol dissectors when available.

---

## 3. Critical Technical Challenges & Engineering Solutions

1. **Streaming AES-GCM Without Memory Exhaustion:**
   - *Challenge:* Forensic disk images and memory dumps frequently exceed available system RAM (e.g., 64 GB raw disk images). Standard `cipher.encrypt(data)` loads the entire file into memory.
   - *Solution:* Implemented 64 KB streaming encryption and decryption. During decryption, data is streamed into an isolated `.part` file, and `cipher.verify(tag)` is executed before committing the file to disk via atomic `os.replace`.
2. **Encrypted Container Header Tampering:**
   - *Challenge:* In naive GCM implementations, only the ciphertext is authenticated; attackers can mutate file metadata (such as iteration counts or version tags) without failing decryption MAC tags.
   - *Solution:* Version 2 feeds the complete 41-byte header into `cipher.update(header)` as Additional Authenticated Data (AAD). Any byte flip in magic bytes, version, iteration count, salt, or nonce causes `verify()` to fail cryptographically.
3. **Dirty Data & Encoding Inconsistencies in Carved Disk Exports:**
   - *Challenge:* Forensically carved or exported MFT CSVs frequently contain embedded NUL bytes (`0x00`), mixed UTF-8 BOM, UTF-16LE, and CP1252 encodings that cause standard Python `csv.reader` to throw `Error: line contains NUL`.
   - *Solution:* Built an encoding-detection wrapper that sanitizes embedded NUL characters on the fly before CSV parsing.
4. **Stateful Multi-Segment TCP Stream Reassembly in Pure Python:**
   - *Challenge:* TLS `ClientHello` packets and HTTP headers frequently span multiple TCP segments. Inspecting single packets misses target hostnames or truncated SNI fields.
   - *Solution:* Implemented a per-flow TCP segment buffer in Scapy fallback mode that tracks sequence numbers, detects HTTP `\r\n\r\n` boundaries, and reads TLS record lengths to reassemble complete handshakes prior to parsing.

---

## 4. Key Security Decisions

- **Fail-Safe Atomic Rollback:** Unauthenticated data is never committed to disk. If a password is wrong or an authentication tag fails, the temporary `.part` file is deleted immediately.
- **Integrity vs Authenticity Separation:** SHA-256 alone only proves bit-stream integrity. Anyone with access to the evidence can alter a file and recalculate a SHA-256 hash. To prove *authenticity* (provenance), the suite supports HMAC-SHA256 signing using an out-of-band secret key.
- **CLI Password Exposure Prevention:** Passing credentials via command-line arguments exposes passwords in OS process listings (`ps` / Task Manager) and shell history files (`.bash_history`). Supported interactive `getpass` prompts and `--password-env` to prevent exposure.
- **Safe Capture Interruption:** `wifi_sniffer.py` traps `KeyboardInterrupt` (Ctrl+C) to safely flush all captured packets to disk, preventing PCAP header corruption.

---

## 5. Technical Interview Questions & Expert Answers

### Module 1: Cryptographic Evidence Preservation (`crypto_lab`)

#### Q1: Why did you choose AES-GCM over AES-CBC with HMAC?
> **Answer:** AES-GCM is an Authenticated Encryption with Associated Data (AEAD) mode that provides both confidentiality and integrity in a single cryptographic primitive. Unlike AES-CBC with HMAC, which requires careful implementation of the "Encrypt-then-MAC" paradigm to prevent padding oracle attacks and timing leaks, AES-GCM natively computes a GMAC authentication tag while encrypting. Additionally, GCM supports Additional Authenticated Data (AAD), enabling us to bind container metadata (like iteration counts and version flags) into the MAC tag.

#### Q2: What is Additional Authenticated Data (AAD), and how is it used in your Version 2 format?
> **Answer:** AAD is plaintext data passed to an AEAD cipher that is authenticated by the MAC tag but not encrypted. In our Version 2 format, the entire 41-byte file header (8-byte magic `FENCRYPT`, 1-byte version `0x02`, 4-byte iteration count, 16-byte salt, and 12-byte nonce) is fed into the cipher via `cipher.update(header)`. If an adversary alters even a single bit in the header (e.g. tampering with the iteration count to force a weaker key derivation), the final `cipher.verify(tag)` fails cryptographically.

#### Q3: How does your tool prevent leaking unauthenticated plaintext if decryption fails midway?
> **Answer:** We employ fail-safe streaming decryption. Instead of writing directly to the target destination or holding gigabytes in RAM, plaintext is streamed into an isolated temporary file (`<target>.part`). The trailing 16-byte GCM authentication tag is only validated once the entire ciphertext stream has been processed. If `cipher.verify(tag)` succeeds, we atomically commit the temporary file to its final destination using `os.replace`. If verification fails, the temporary file is securely removed immediately, ensuring zero partial plaintext remains on disk.

#### Q4: Why is PBKDF2 used instead of a simple SHA-256 hash of the password?
> **Answer:** A single SHA-256 hash of a password can be computed billions of times per second on modern GPUs, making it trivially vulnerable to dictionary and brute-force attacks. PBKDF2-HMAC-SHA256 applies a key-stretching algorithm repeated across hundreds of thousands of iterations (defaulting to 600,000 in V2), combined with a cryptographically secure 16-byte unique salt. This increases the computational cost of evaluating each password candidate, rendering offline dictionary attacks computationally infeasible.

#### Q5: What is the difference between evidence integrity and evidence authenticity?
> **Answer:** Evidence integrity guarantees that the bits of a file have not changed between two points in time; this is typically verified using an unkeyed cryptographic hash like SHA-256. However, SHA-256 provides no proof of authenticity: an attacker with write access could modify the evidence file and regenerate a valid SHA-256 hash. Authenticity proves that the evidence and its custody record were generated by an authorized party. We achieve this by calculating an HMAC-SHA256 signature over the evidence record using an out-of-band secret key.

#### Q6: Why must the AES-GCM nonce never be reused with the same key?
> **Answer:** In Galois/Counter Mode, reusing a nonce with the same key destroys the authenticity guarantee. Specifically, an attacker who intercepts two ciphertexts encrypted with the same key and nonce can XOR the ciphertexts to eliminate the keystream and uncover the XOR of the two plaintexts. More critically, nonce reuse allows an attacker to solve a system of linear equations over Galois Field $GF(2^{128})$ to recover the internal GMAC hash key $H$, allowing them to forge authentication tags for arbitrary messages. Our tool generates a fresh, cryptographically random 12-byte nonce for every encryption operation.

#### Q7: How does your tool handle large multi-gigabyte forensic files without running out of memory?
> **Answer:** We read and encrypt/decrypt files in 64 KB streaming chunks using Python file buffers. The PyCryptodome AES-GCM cipher object updates its internal cryptographic state incrementally across chunk boundaries. This guarantees that memory utilization remains constant at approximately a few megabytes, regardless of whether we are encrypting a 1 KB text file or a 100 GB forensic disk image.

#### Q8: What security risks are associated with CLI password arguments, and how did you mitigate them?
> **Answer:** Passing passwords via command-line arguments (`-p <password>`) exposes them to two major vectors: (1) process table inspection via `ps` or Windows Task Manager by other local users, and (2) shell history files (`.bash_history` or PowerShell command history). We mitigated this by defaulting to non-echoing terminal prompts via `getpass.getpass()`, providing `--password-env` to read credentials from environment variables, and printing an explicit security warning whenever `-p` is supplied.

#### Q9: How is backward compatibility maintained between Version 1 and Version 2 containers?
> **Answer:** The decryption routine inspects the 9th byte of the file header (the version byte). If it reads `0x01`, it parses the 37-byte legacy header (fixed 200,000 iterations, no AAD binding) and invokes standard AES-GCM decryption. If it reads `0x02`, it parses the 41-byte header (extracting the 4-byte iteration count) and binds the header into the cipher as AAD. This ensures legacy evidence files remain verifiable while all newly encrypted artifacts benefit from AAD hardening.

#### Q10: How would you expand this tool for enterprise forensic evidence management?
> **Answer:** In an enterprise environment, relying solely on shared passwords introduces key escrow risks. I would implement hybrid envelope encryption: generating an ephemeral symmetric AES-256 data encryption key (DEK) for the evidence container, and then encrypting that DEK using an asymmetric RSA-4096 or ECDSA public key held by the organization’s forensic laboratory, or integrating with a Hardware Security Module (HSM) / Cloud KMS.

---

### Module 2: NTFS MFT & Recycle Bin Timeline Reconstruction (`disk_forensics`)

#### Q11: What is the NTFS Master File Table (MFT) and what attributes are most critical for forensic analysts?
> **Answer:** The MFT is the core database of the NTFS file system, where every file and folder is represented by at least one 1024-byte record. The two most critical attributes are:
> 1. `$STANDARD_INFORMATION` (Attribute 0x10): Contains DOS permissions, security IDs, and the standard MACB timestamps. These timestamps are updated during regular file access but can be altered by user-mode APIs (timestomping).
> 2. `$FILE_NAME` (Attribute 0x30): Contains the UTF-16 file name, parent directory record reference, file size, and independent MACB timestamps. These timestamps are updated by the Windows kernel driver and are generally immune to standard user-mode timestomping tools.

#### Q12: Why is clearing the `InUse` flag in an MFT entry considered a heuristic indicator of deletion rather than absolute proof?
> **Answer:** When a file is deleted in NTFS, the operating system marks the MFT record as unallocated by clearing the `InUse` bit (`0x01`) in the record header. However, this is an investigative heuristic because:
> - The record remains intact only until the OS allocates that specific MFT index to a new file.
> - An unallocated MFT entry does not guarantee that the associated disk data clusters are intact.
> - In high-activity environments, rapid record reuse can lead to false correlations. Conclusive findings require cross-corroboration with the `$UsnJrnl` (USN Journal) and the `$LogFile`.

#### Q13: How does modern Windows handle deletions into the Recycle Bin, and how do you correlate `$I` and `$R` files?
> **Answer:** In Windows Vista and later, files sent to the Recycle Bin are renamed and stored in `\$Recycle.Bin\<User_SID>\` as two paired files sharing an identical random identifier:
> - `$R<random>.<ext>`: Contains the actual raw file payload.
> - `$I<random>.<ext>`: A 544-byte (Win 10/11) or 32-byte (Win Vista/7) metadata header containing the original file size, the original absolute directory path, and a 64-bit Windows FILETIME deletion timestamp.
> Our tool parses `$I` exports to recover the original filename, path, and deletion event, linking it back to active or unallocated MFT records.

#### Q14: What is timestomping, and how can an investigator detect it using your tool’s timeline?
> **Answer:** Timestomping is an anti-forensics technique where an attacker deliberately modifies `$STANDARD_INFORMATION` (0x10) timestamps to blend malware with legitimate system files (e.g., setting a malware creation timestamp to match `explorer.exe`). It is detected by comparing `$STANDARD_INFORMATION` timestamps against `$FILE_NAME` (0x30) timestamps. If `$STANDARD_INFORMATION` indicates the file was created in 2021, but `$FILE_NAME` shows creation in 2026, timestomping has occurred.

#### Q15: How does your ingestion engine handle corrupted or non-standard forensic CSV exports?
> **Answer:** Forensically carved or exported files frequently contain embedded NUL bytes (`0x00`) or non-UTF-8 character encodings (e.g. UTF-8 with BOM, UTF-16LE, CP1252) that break standard CSV parsers. Our engine wraps the raw binary stream with an encoding-detection routine, sanitizes embedded NUL bytes prior to ingestion, and utilizes case-insensitive key normalization so variations like `Filename` vs `File Name` are mapped seamlessly.

#### Q16: Why is chronological sorting of file system timelines essential during incident response?
> **Answer:** Attackers leave breadcrumbs across multiple files in rapid succession (e.g., writing a dropper, creating a persistence registry run key, running a PowerShell script, and deleting the dropper into the Recycle Bin within seconds). Merging and sorting disparate artifact timestamps chronologically allows an investigator to build a continuous narrative of adversary actions.

#### Q17: What are the limitations of relying on CSV exports of MFT data rather than parsing raw `$MFT` binaries?
> **Answer:** CSV exports rely on the parsing logic of the upstream triage tool (such as MFTECmd or FTK). CSVs typically discard low-level structures such as Alternate Data Streams (ADS), non-resident data cluster runlists, update sequence fixup values, and Slack space. For deep root-cause forensics or raw file carving, direct binary examination of the `$MFT` image is required.

#### Q18: How does `merge_timelines.py` handle schema discrepancies between different forensic artifacts?
> **Answer:** Different tools produce different CSV columns. `merge_timelines.py` performs dynamic schema reconciliation by creating a prioritized union of common forensic keys (`timestamp`, `source_artifact`, `event`, `filename`, `record`, `size`, `fullpath`, `original_path`, `recycle_name`, `flags`, `deleted`) followed by any extra columns discovered in the input files. Missing values are filled with empty strings, preventing column misalignment.

#### Q19: How did you ensure duplicate records from multiple exports do not skew timeline analysis?
> **Answer:** When ingesting multiple reports, identical events may be extracted twice. `merge_timelines.py` implements an exact-match deduplication pass that indexes full row signatures. However, if two records share a timestamp and filename but originate from different artifacts (e.g., an MFT event vs a Recycle Bin event), the `source_artifact` tag preserves both entries so evidentiary provenance is not lost.

#### Q20: What is the NTFS USN Journal, and how does it complement MFT analysis?
> **Answer:** The Update Sequence Number (USN) Change Journal (`$UsnJrnl:$J`) records changes made to files and directories on the volume with reason codes (e.g., `FILE_CREATE`, `DATA_EXTEND`, `FILE_DELETE`). While an unallocated MFT entry only preserves the last known state of an entry, the USN Journal provides a high-resolution delta log of every write and delete transaction, allowing investigators to detect files that were created and deleted so rapidly that their MFT records were completely overwritten.

---

### Module 3: Network DPI & Protocol Forensics (`network_forensics`)

#### Q21: What is the Server Name Indication (SNI) in TLS, and why is it invaluable in network forensics?
> **Answer:** SNI is an extension to the TLS protocol (RFC 6066) included in the initial unencrypted `ClientHello` handshake message. It specifies the hostname of the server the client is attempting to connect to. In modern encrypted networks where payload contents cannot be read, SNI allows investigators to identify the exact target domains of outbound malware beacons and data exfiltration without needing the private decryption keys.

#### Q22: What is Encrypted Client Hello (ECH) and how does it impact SNI extraction?
> **Answer:** ECH (formerly ESNI, specified in RFC 8446 extensions) encrypts the entire `ClientHello` payload using a public key published in the target domain’s DNS HTTPS/SVCB records. When ECH is adopted, the SNI is no longer transmitted in plaintext, leaving only an outer public-facing server name. In such environments, forensic analysts must rely on DNS query logs, IP reputation, TLS certificate fingerprinting (JA4/JA4+), and endpoint process-to-network telemetry.

#### Q23: Why did you implement stateful TCP stream reassembly in your Scapy fallback engine?
> **Answer:** TCP is a byte-stream protocol where packets may arrive fragmented, out of order, or split across multiple Maximum Transmission Units (MTUs). Naive packet-by-packet inspection fails when an HTTP request header or TLS `ClientHello` spans multiple packets. Our reassembly engine maintains per-flow buffers keyed by `(src_ip, src_port, dst_ip, dst_port)`, assembling packets sequentially until standard protocol boundaries (such as `\r\n\r\n` for HTTP or record lengths for TLS) are satisfied.

#### Q24: How does your tool differentiate between IPv4, IPv6, ICMP, and ARP traffic?
> **Answer:** The protocol analyzer avoids simplistic port-based assumptions. It inspects Scapy layer types directly: evaluating `IPv6` vs `IP` layers, checking layer protocol numbers (e.g., IP protocol 1 for ICMP, 58 for ICMPv6, 6 for TCP, 17 for UDP), and inspecting Ethernet frames for ARP (`0x0806`). This ensures tunneling protocols and non-TCP traffic are accurately accounted for in the forensic report.

#### Q25: What are the forensic differences between Scapy and PyShark/TShark?
> **Answer:** TShark (driven via PyShark) relies on Wireshark's mature C-based protocol dissection library (`libwireshark`), providing deep protocol dissection across thousands of protocols, deep TLS extension parsing, and chunked HTTP transfer decoding. However, it requires an external binary installation. Scapy is a pure-Python library with zero external dependencies, making it portable and easily embedded into autonomous agents, but requiring custom stateful reassembly logic.

#### Q26: How did you ensure live packet capture in `wifi_sniffer.py` is safe against sudden termination?
> **Answer:** During live incident response, analysts often terminate captures via `KeyboardInterrupt` (Ctrl+C). Naive capture scripts terminate ungracefully, often dropping buffered packets or leaving PCAP file headers unfinalized. We implemented explicit signal interception that catches `KeyboardInterrupt`, cleanly commits all in-memory packets to the output PCAP via `wrpcap`, and calculates the final SHA-256 custody hash before terminating.

#### Q27: How can DNS query extraction assist in identifying Command-and-Control (C2) activity?
> **Answer:** Malware typically contacts C2 infrastructure via domain names generated through Domain Generation Algorithms (DGA) or uses DNS tunneling for stealthy exfiltration. By extracting and normalizing all DNS queries from a PCAP, analysts can identify high-entropy domain names, unusual query frequencies, long TXT record requests, and internal hosts querying non-standard external DNS resolvers.

#### Q28: What is JA3/JA4 fingerprinting, and how does it complement TLS SNI extraction?
> **Answer:** JA3/JA4 produces a cryptographic hash of the client's TLS `ClientHello` configuration (TLS version, accepted cipher suites, extensions, and elliptic curve algorithms). Because malware families and attack tools (e.g. Cobalt Strike, Metasploit, Python requests) often use specific TLS client configurations regardless of the domain they target, JA3/JA4 hashes allow investigators to fingerprint the underlying malware agent even if the SNI domain is randomized or masked.

#### Q29: What is the significance of the PCAP evidence hash file (`.evidence.txt`)?
> **Answer:** In legal proceedings, opposing counsel can challenge the admissibility of network traffic evidence if the chain of custody is broken. Computing a cryptographic SHA-256 hash immediately upon capture and recording the timestamp, packet count, and capture parameters provides proof of data integrity, proving the PCAP was not altered after acquisition.

#### Q30: How would you scale this network forensics pipeline for 10 Gbps enterprise networks?
> **Answer:** Pure-Python packet capture and analysis cannot sustain 10 Gbps saturation without massive packet drops. In high-speed enterprise environments, I would deploy kernel-bypass packet acquisition frameworks like DPDK (Data Plane Development Kit) or AF_XDP combined with Zeek or Suricata for real-time protocol parsing and metadata generation, using our Python suite for targeted offline forensic triage of carved artifact sessions.
