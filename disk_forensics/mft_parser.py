"""
mft_parser.py - Robust NTFS Master File Table (MFT) CSV Artifact Parser
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Parses MFT CSV exports from Autopsy, FTK, MFTECmd, or custom forensic extractions
- Auto-detects file encodings (UTF-8, UTF-8-SIG, UTF-16, CP1252)
- Normalizes diverse timestamp formats to standardized ISO-8601 strings
- Applies heuristic deleted-file detection based on MFT InUse bits and EntryFlags
- Generates comprehensive normalized reports (mft_report.csv) and event timelines (mft_timeline.csv)

NOTE ON HEURISTIC DELETION:
In NTFS, MFT record header flag bit 0x01 indicates whether a record is currently in use.
When a file is deleted, this bit is cleared, and EntryFlags may transition to 'Deleted'.
However, this is an investigative heuristic: MFT records can be repurposed, overwritten,
or out-of-sync with USN journal logs. It should be correlated with other file system artifacts.
"""

import argparse
import csv
import io
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple

try:
    from dateutil import parser as dparser
except ImportError:
    dparser = None

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("mft_parser")


def open_csv_multienconding(filepath: str) -> Tuple[csv.DictReader, object]:
    """
    Attempt opening a CSV file with automatic fallback for forensic export encodings:
    UTF-8-SIG (handles UTF-8 with/without BOM), UTF-16, and CP1252/Latin-1.
    Cleans embedded NUL bytes from carved/raw files.
    Returns (DictReader, file_object).
    """
    encodings_to_try = ["utf-8-sig", "utf-16", "cp1252", "latin-1"]
    for enc in encodings_to_try:
        try:
            f = open(filepath, "r", encoding=enc, errors="strict")
            content = f.read(4096)
            f.seek(0)
            # If NUL bytes are present (common in carved artifacts), wrap in cleaned stream
            if "\x00" in content:
                raw_text = f.read().replace("\x00", "")
                f.close()
                clean_stream = io.StringIO(raw_text)
                reader = csv.DictReader(clean_stream)
                _ = reader.fieldnames
                return reader, clean_stream
            reader = csv.DictReader(f)
            _ = reader.fieldnames
            return reader, f
        except (UnicodeError, csv.Error):
            continue

    # Fallback with error replacement and NUL cleaning
    f = open(filepath, "r", encoding="utf-8", errors="replace")
    raw_text = f.read().replace("\x00", "")
    f.close()
    clean_stream = io.StringIO(raw_text)
    reader = csv.DictReader(clean_stream)
    return reader, clean_stream


def parse_timestamp(ts_str: str) -> str:
    """Normalize timestamp string into ISO format (YYYY-MM-DD HH:MM:SS) in UTC or return empty string."""
    if not ts_str or not ts_str.strip():
        return ""
    ts_str = ts_str.strip()

    # Support Unix epoch timestamp (integer or float seconds)
    try:
        val = float(ts_str)
        if 946684800 <= val <= 4102444800:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    if dparser:
        try:
            parsed = dparser.parse(ts_str)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc)
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts_str
    return ts_str


def is_deleted_heuristic(flags: str, inuse: str) -> bool:
    """
    Investigative heuristic to determine if an MFT entry represents a deleted record.
    Checks explicit inuse flags ('0', 'false'), numeric flag bitmasks, and keywords in EntryFlags.
    """
    if inuse:
        s = inuse.strip().lower()
        if s in ("0", "false", "no"):
            return True
        if s in ("1", "true", "yes"):
            return False

    if flags:
        f_lower = flags.strip().lower()
        if "deleted" in f_lower or "unalloc" in f_lower:
            return True
        if "inuse" in f_lower or "alloc" in f_lower:
            return False

        # Support numeric flag bitmasks (e.g., 0, 1, 2, 3 from MFTECmd/FTK exports)
        try:
            val = int(flags.strip(), 0)
            # In NTFS MFT: Bit 0 (0x01) = InUse, Bit 1 (0x02) = Directory
            return (val & 0x01) == 0
        except ValueError:
            pass

    return False


def get_field_insensitive(row: dict, candidate_keys: List[str]) -> str:
    """Retrieve value from dict matching any candidate key case-insensitively."""
    key_map = {k.lower().strip(): k for k in row.keys() if k}
    for cand in candidate_keys:
        cand_lower = cand.lower().strip()
        if cand_lower in key_map:
            val = row.get(key_map[cand_lower])
            if val is not None:
                return str(val).strip()
    return ""


def parse_mft(path: str) -> List[Dict[str, str]]:
    """Parse an MFT CSV export into structured records."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"MFT file not found: {path}")

    reader, f = open_csv_multienconding(path)
    rows = []
    try:
        for idx, r in enumerate(reader, start=1):
            if not r or all(v is None or v == "" for v in r.values()):
                continue

            record_num = get_field_insensitive(r, ["RecordNumber", "Record", "EntryNumber", "MFTEntry", "ID"])
            filename = get_field_insensitive(r, ["Filename", "FileName", "Name", "File Name"])
            fullpath = get_field_insensitive(r, ["FullPath", "Path", "Full Path", "Directory", "ParentPath"])
            created = parse_timestamp(get_field_insensitive(r, ["Created", "CreationTime", "Created0x10", "Created0x30", "FileCreated"]))
            modified = parse_timestamp(get_field_insensitive(r, ["Modified", "LastModified", "Modified0x10", "Modified0x30", "FileModified"]))
            accessed = parse_timestamp(get_field_insensitive(r, ["Accessed", "LastAccessed", "Accessed0x10", "Accessed0x30", "LastAccess"]))
            flags = get_field_insensitive(r, ["EntryFlags", "Flags", "Status"])
            inuse = get_field_insensitive(r, ["InUse", "Allocated", "IsAllocated", "Active"])
            size = get_field_insensitive(r, ["Size", "FileSize", "AllocatedSize", "Length"])

            deleted = is_deleted_heuristic(flags, inuse)

            rows.append({
                "record": record_num or str(idx),
                "filename": filename,
                "fullpath": fullpath,
                "created": created,
                "modified": modified,
                "accessed": accessed,
                "size": size,
                "flags": flags,
                "inuse": inuse,
                "deleted": str(deleted),
            })
    finally:
        f.close()

    logger.info("Successfully parsed %d records from %s", len(rows), path)
    return rows


def write_reports(rows: List[Dict[str, str]], basedir: str = None, report_out: str = None, timeline_out: str = None) -> Tuple[str, str]:
    """Generate both a normalized MFT report and a flattened event timeline CSV."""
    if not basedir:
        basedir = "."

    rep_path = report_out or os.path.join(basedir, "mft_report.csv")
    tl_path = timeline_out or os.path.join(basedir, "mft_timeline.csv")

    # 1. Normalized Report
    rep_headers = ["record", "filename", "fullpath", "created", "modified", "accessed", "size", "flags", "inuse", "deleted"]
    with open(rep_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rep_headers)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in rep_headers})
    logger.info("Normalized MFT report written to: %s", rep_path)

    # 2. Timeline CSV (one event per timestamp)
    tl_headers = ["timestamp", "source_artifact", "event", "filename", "record", "size", "fullpath", "flags", "deleted"]
    with open(tl_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=tl_headers)
        writer.writeheader()
        for r in rows:
            for event_type in ("created", "modified", "accessed"):
                ts = r.get(event_type, "")
                if ts:
                    writer.writerow({
                        "timestamp": ts,
                        "source_artifact": "MFT",
                        "event": event_type,
                        "filename": r.get("filename", ""),
                        "record": r.get("record", ""),
                        "size": r.get("size", ""),
                        "fullpath": r.get("fullpath", ""),
                        "flags": r.get("flags", ""),
                        "deleted": r.get("deleted", ""),
                    })
    logger.info("MFT timeline written to: %s", tl_path)

    return rep_path, tl_path


def main():
    parser = argparse.ArgumentParser(
        description="NTFS MFT CSV Parser — Extract records, normalize timestamps, and generate timelines."
    )
    parser.add_argument("mft_csv", help="Path to exported MFT CSV file")
    parser.add_argument("-o", "--outdir", default=None, help="Output directory for generated reports")
    parser.add_argument("--report", default=None, help="Custom output path for mft_report.csv")
    parser.add_argument("--timeline", default=None, help="Custom output path for mft_timeline.csv")

    args = parser.parse_args()

    base_dir = args.outdir
    if not base_dir:
        base_dir = os.path.dirname(args.mft_csv) or "."

    rows = parse_mft(args.mft_csv)
    write_reports(rows, basedir=base_dir, report_out=args.report, timeline_out=args.timeline)


if __name__ == "__main__":
    main()
