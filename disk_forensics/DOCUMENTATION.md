# Disk Artifact Parser — NTFS MFT & Recycle Bin
**Project:** Disk Artifact Parser & Timeline Reconstructor
**Module:** `disk_forensics`
**Purpose:** Parse NTFS MFT CSV exports and Recycle Bin CSV exports to build a merged forensic timeline, recover deleted filenames, and produce analysis-ready CSVs.

---

## 1. Project Overview
This project provides a robust toolset to analyze file system artifacts from Windows systems with a **CSV-first** approach. It parses exported NTFS MFT entries (CSV) and Recycle Bin exports (CSV), normalizes timestamps, flags likely deleted entries, tracks source artifacts, and merges timelines into a single chronological CSV for investigation and visualization.

**Why CSV-first?**
- Exporting CSV from Autopsy, EnCase, FTK Imager, or MFTECmd is reliable and easy to reproduce across varied environments.
- Enables focus on the analysis logic (timeline building, deletion heuristics, schema reconciliation, reporting).
- Modularity allows future expansion into raw binary `$MFT` parsing or USN journal correlation.

---

## 2. Forensic Background & Interview Talking Points

### What is the Master File Table (MFT)?
- The **Master File Table (MFT)** is the central metadata database of the NTFS file system.
- Every file and directory on an NTFS volume has at least one 1024-byte record in the MFT containing core attributes:
  - `$STANDARD_INFORMATION` (0x10): Timestamps (MACB), file permissions, DOS flags. Often modified by user actions.
  - `$FILE_NAME` (0x30): File name, parent directory reference, and independent timestamps (less prone to timestomping).
  - `$DATA` (0x80): Actual content (resident if < ~700 bytes, non-resident cluster runs otherwise).
- Analysts leverage MFT data to reconstruct file creation, modification, and access sequences even if files have been deleted.

### Why Recycle Bin Artifacts Matter
- In modern Windows (Vista through Windows 11), files deleted to the Recycle Bin create pairs of files in `$Recycle.Bin\<User_SID>\`:
  - `$I<random>.<ext>`: Metadata file containing the file's original file size, original full path, and deletion timestamp.
  - `$R<random>.<ext>`: The actual file content.
- Correlating Recycle Bin `$I` records with MFT records allows an investigator to pinpoint exactly when a user initiated deletion and what directory the file originated from.

---

## 3. Toolset Components & Workflow

### `mft_parser.py`
- **Input:** MFT CSV export (e.g., `sample_mft.csv`).
- **Processing:**
  - Multi-encoding detection (UTF-8, UTF-8-BOM, UTF-16, CP1252) with NUL-byte cleansing.
  - Flexible timestamp parsing: US format (`MM/DD/YYYY HH:MM:SS`), ISO-8601 with `Z` timezone/microsecond offsets, and Unix epoch (seconds/milliseconds).
  - Heuristic deletion detection: evaluation of `InUse` status, textual flags, and numeric bitmasks (`(flags & 0x01) == 0`).
  - Source tracking: tags events with `source_artifact=MFT` and preserves `record` and `size`.
- **Outputs:**
  - `mft_report.csv`: Complete normalized record dump with deletion heuristic flags.
  - `mft_timeline.csv`: Flattened timestamp events (`created`, `modified`, `accessed`).

### `recycle_parser.py`
- **Input:** Recycle Bin CSV export (e.g., `sample_recycle.csv`).
- **Processing:**
  - Normalizes deletion timestamps across alternate date formats.
  - Extracts original paths, sizes, and `$R`/`$I` pairings.
  - Source tracking: tags events with `source_artifact=RecycleBin`.
- **Outputs:**
  - `recycle_report.csv`: Parsed Recycle Bin records.
  - `recycle_timeline.csv`: Deletion events tagged for timeline merging.

### `merge_timelines.py`
- **Input:** `mft_timeline.csv` + `recycle_timeline.csv` (or any arbitrary timeline CSVs).
- **Processing:**
  - Dynamic schema reconciliation: orders prioritized columns (`timestamp`, `source_artifact`, `event`, `filename`, `record`, `size`, `fullpath`, `original_path`, `recycle_name`, `flags`, `deleted`) followed by any extra metadata fields.
  - Exact deduplication: eliminates duplicate rows while preserving conflicting evidence from distinct sources.
  - Strict chronological sorting.
- **Output:**
  - `merged.csv`: Complete chronological master timeline combining file activity and deletions.

---

## 4. Investigative Limitations & Caveats

1. **Heuristic Deletion Flagging:**
   In NTFS, an MFT record is marked unallocated when the record header flag bit `0x01` (`InUse`) is cleared. While this signals deletion, records may be reallocated quickly on busy drives. MFT flags must be corroborated with the NTFS `$UsnJrnl` and `$LogFile`.
2. **Timestomping Awareness:**
   `$STANDARD_INFORMATION` (0x10) timestamps can be altered via user-mode APIs (timestomping), while `$FILE_NAME` (0x30) timestamps are updated by the NTFS kernel driver. Comparing the two is critical in real-world investigations.
3. **CSV Export Limitations vs Raw NTFS Dissection:**
   - Pre-parsed CSV files lose low-level attributes like Alternate Data Streams (ADS), runlists, and fixup values.
   - Field naming conventions vary across tools (e.g., `FileName` vs `Filename`, `OriginalPath` vs `Original Path`). The parsers employ fuzzy key lookups, but raw forensic acquisition is necessary for full evidence preservation.

---

## 5. Verification & Testing

Run the automated test suite:
```powershell
py -m unittest tests/test_disk_forensics.py
```
Covers 11 unit and integration test cases.
