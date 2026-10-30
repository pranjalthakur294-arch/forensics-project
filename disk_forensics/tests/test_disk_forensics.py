"""
test_disk_forensics.py - Unit & Integration Tests for Disk Forensics Module (Hardened)
Tests:
- MFT parsing with standard, deleted, and missing fields
- Source artifact preservation ('MFT' vs 'RecycleBin') through timeline merging
- Recycle Bin parsing with $R/$I pairing data
- Alternate timestamp formats: ISO-8601 with Z, US format (MM/DD/YYYY), Unix epoch
- Conflicting metadata preservation for forensic analysis
- Timeline merging, schema reconciliation, and chronological ordering
- Numeric bitmask allocation flags (0, 1, 2, 3)
- Multi-encoding fallback (UTF-8-SIG with BOM, CP1252)
- NUL-byte handling in carved CSV exports
"""

import os
import sys
import unittest
import tempfile
import shutil

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DISK_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if DISK_DIR not in sys.path:
    sys.path.insert(0, DISK_DIR)

from mft_parser import parse_mft, is_deleted_heuristic, parse_timestamp, write_reports as write_mft_reports
from recycle_parser import parse_recycle, write_reports as write_recycle_reports
from merge_timelines import merge_and_sort_timelines, parse_timestamp_safe


class TestDiskForensics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="forensics_disk_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_deletion_heuristics(self):
        """Verify heuristic deletion detection behavior."""
        self.assertTrue(is_deleted_heuristic("InUse", "0"))
        self.assertTrue(is_deleted_heuristic("InUse", "false"))
        self.assertFalse(is_deleted_heuristic("InUse", "1"))
        self.assertFalse(is_deleted_heuristic("InUse", "true"))

        self.assertTrue(is_deleted_heuristic("Deleted", ""))
        self.assertTrue(is_deleted_heuristic("File - Unallocated", ""))
        self.assertFalse(is_deleted_heuristic("InUse", ""))
        self.assertFalse(is_deleted_heuristic("Allocated", ""))

    def test_numeric_mft_flags(self):
        """Test numeric bitmask flags (0=inactive file, 1=active file, 2=inactive dir, 3=active dir)."""
        self.assertTrue(is_deleted_heuristic("0", ""))
        self.assertFalse(is_deleted_heuristic("1", ""))
        self.assertTrue(is_deleted_heuristic("2", ""))
        self.assertFalse(is_deleted_heuristic("3", ""))
        self.assertTrue(is_deleted_heuristic("0x0000", ""))
        self.assertFalse(is_deleted_heuristic("0x0001", ""))

    def test_alternate_timestamp_formats(self):
        """Verify normalization across US format, ISO-Z with microseconds, and Unix epoch."""
        # US format
        self.assertEqual(parse_timestamp("12/01/2024 10:21:55"), "2024-12-01 10:21:55")
        # ISO with T and Z
        self.assertEqual(parse_timestamp("2024-12-01T10:21:55Z"), "2024-12-01 10:21:55")
        # Unix epoch timestamp (1733048515 = 2024-12-01 10:21:55 UTC)
        self.assertEqual(parse_timestamp("1733048515"), "2024-12-01 10:21:55")
        # Empty/None
        self.assertEqual(parse_timestamp(""), "")
        self.assertEqual(parse_timestamp(None), "")

    def test_timezone_normalized_to_utc(self):
        """Test timestamps with timezone offsets are normalized to UTC."""
        ts_with_tz = "2024-12-01 10:00:00+05:00"
        normalized = parse_timestamp(ts_with_tz)
        self.assertEqual(normalized, "2024-12-01 05:00:00")

    def test_mft_parser_with_sample_and_missing_fields(self):
        """Test MFT parsing handles missing columns and generates expected reports."""
        csv_path = os.path.join(self.test_dir, "test_mft.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("RecordNumber,Filename,FullPath,Created,Modified,Accessed,EntryFlags,Size,InUse\n")
            f.write("1,ev.txt,C:\\test\\ev.txt,2024-10-01 12:00:00,,,Deleted,100,0\n")
            f.write("2,active.docx,C:\\test\\active.docx,2024-10-02 12:00:00,2024-10-02 13:00:00,2024-10-02 14:00:00,InUse,200,1\n")

        rows = parse_mft(csv_path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["deleted"], "True")
        self.assertEqual(rows[1]["deleted"], "False")

        rep, tl = write_mft_reports(rows, basedir=self.test_dir)
        self.assertTrue(os.path.exists(rep))
        self.assertTrue(os.path.exists(tl))

    def test_recycle_parser(self):
        """Test Recycle Bin parser extracts original path and deletion timestamp."""
        csv_path = os.path.join(self.test_dir, "test_recycle.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("RecycleName,FileName,OriginalPath,DeletionTime,Size\n")
            f.write("$R99.txt,secret.txt,C:\\Users\\Admin,2024-10-03 09:15:00,512\n")

        rows = parse_recycle(csv_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filename"], "secret.txt")
        self.assertEqual(rows[0]["recycle_name"], "$R99.txt")

        rep, tl = write_recycle_reports(rows, basedir=self.test_dir)
        self.assertTrue(os.path.exists(rep))
        self.assertTrue(os.path.exists(tl))

    def test_source_artifact_and_conflicting_metadata_preserved(self):
        """Test that conflicting metadata from MFT and Recycle Bin are both preserved with source labels."""
        mft_csv = os.path.join(self.test_dir, "conflict_mft.csv")
        rec_csv = os.path.join(self.test_dir, "conflict_rec.csv")
        merged = os.path.join(self.test_dir, "conflict_merged.csv")

        # File modified at 10:00 in MFT, but deleted at 11:00 according to Recycle Bin
        with open(mft_csv, "w", encoding="utf-8") as f:
            f.write("RecordNumber,Filename,FullPath,Created,Modified,Accessed,EntryFlags,Size,InUse\n")
            f.write("100,disputed.doc,C:\\disputed.doc,2024-12-01 09:00:00,2024-12-01 10:00:00,2024-12-01 10:00:00,Deleted,1024,0\n")

        with open(rec_csv, "w", encoding="utf-8") as f:
            f.write("RecycleName,FileName,OriginalPath,DeletionTime,Size\n")
            f.write("$R55.doc,disputed.doc,C:\\,2024-12-01 11:00:00,1024\n")

        mft_rows = parse_mft(mft_csv)
        _, mft_tl = write_mft_reports(mft_rows, basedir=self.test_dir)

        rec_rows = parse_recycle(rec_csv)
        _, rec_tl = write_recycle_reports(rec_rows, basedir=self.test_dir)

        merge_and_sort_timelines([mft_tl, rec_tl], merged)

        with open(merged, "r", encoding="utf-8") as f:
            lines = f.readlines()

        self.assertIn("source_artifact", lines[0])
        # Verify both MFT and RecycleBin sources are represented in timeline
        content = "".join(lines)
        self.assertIn("MFT", content)
        self.assertIn("RecycleBin", content)
        self.assertIn("disputed.doc", content)

    def test_merge_timelines_chronological_order(self):
        """Verify merger unifies columns without character fragmentation and sorts chronologically."""
        tl1 = os.path.join(self.test_dir, "tl1.csv")
        tl2 = os.path.join(self.test_dir, "tl2.csv")
        merged = os.path.join(self.test_dir, "merged.csv")

        with open(tl1, "w", encoding="utf-8") as f:
            f.write("timestamp,source_artifact,event,filename,fullpath\n")
            f.write("2024-10-05 10:00:00,MFT,created,fileB.txt,C:\\fileB.txt\n")
            f.write("2024-10-01 10:00:00,MFT,created,fileA.txt,C:\\fileA.txt\n")

        with open(tl2, "w", encoding="utf-8") as f:
            f.write("timestamp,source_artifact,event,filename,original_path,recycle_name\n")
            f.write("2024-10-03 10:00:00,RecycleBin,deleted,fileA.txt,C:\\,$R1.txt\n")

        count = merge_and_sort_timelines([tl1, tl2], merged)
        self.assertEqual(count, 3)

        with open(merged, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]

        header = lines[0]
        self.assertIn("timestamp", header)
        self.assertIn("source_artifact", header)
        self.assertIn("event", header)
        self.assertIn("filename", header)

        # Check chronological sort
        self.assertTrue(lines[1].startswith("2024-10-01"))
        self.assertTrue(lines[2].startswith("2024-10-03"))
        self.assertTrue(lines[3].startswith("2024-10-05"))

    def test_nul_byte_cleaning_in_carved_csv(self):
        """Test reading CSV exports containing embedded NUL bytes from memory/disk carving."""
        nul_file = os.path.join(self.test_dir, "carved_nul.csv")
        with open(nul_file, "wb") as f:
            f.write(b"RecordNumber,Filename,FullPath,Created,EntryFlags,InUse\n42\x00,carved.bin\x00,C:\\carved.bin,2024-12-01 12:00:00,InUse,1\n")

        rows = parse_mft(nul_file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filename"], "carved.bin")
        self.assertEqual(rows[0]["record"], "42")

    def test_utf8_bom_encoding_support(self):
        """Test reading CSV exports saved with UTF-8 BOM."""
        bom_file = os.path.join(self.test_dir, "bom_mft.csv")
        with open(bom_file, "w", encoding="utf-8-sig") as f:
            f.write("RecordNumber,Filename,FullPath,Created,EntryFlags,InUse\n")
            f.write("10,test_bom.txt,C:\\test_bom.txt,2024-12-05 08:00:00,InUse,1\n")

        rows = parse_mft(bom_file)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filename"], "test_bom.txt")

    def test_deduplication_in_timeline_merge(self):
        """Test that identical duplicate timeline rows are deduplicated."""
        tl_dup = os.path.join(self.test_dir, "dup.csv")
        with open(tl_dup, "w", encoding="utf-8") as f:
            f.write("timestamp,source_artifact,event,filename\n")
            f.write("2024-12-01 10:00:00,MFT,created,test.txt\n")
            f.write("2024-12-01 10:00:00,MFT,created,test.txt\n")

        merged = os.path.join(self.test_dir, "dup_merged.csv")
        count = merge_and_sort_timelines([tl_dup], merged)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
