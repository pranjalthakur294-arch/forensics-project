"""
recycle_parser.py - Windows Recycle Bin Artifact CSV Parser
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Parses Windows Recycle Bin CSV exports (from Autopsy, FTK, or custom extractions)
- Normalizes deletion timestamps to standard ISO format
- Extracts original file names, original directory paths, $R / $I pairings, and sizes
- Generates structured reports (recycle_report.csv) and event timelines (recycle_timeline.csv)
"""

import argparse
import csv
import io
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple

try:
    from dateutil import parser as dparser
except ImportError:
    dparser = None

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("recycle_parser")


def open_csv_multienconding(filepath: str) -> Tuple[csv.DictReader, object]:
    """Attempt opening a CSV with fallback for UTF-8-SIG, UTF-16, and CP1252, cleaning NUL bytes."""
    encodings_to_try = ["utf-8-sig", "utf-16", "cp1252", "latin-1"]
    for enc in encodings_to_try:
        try:
            f = open(filepath, "r", encoding=enc, errors="strict")
            content = f.read(4096)
            f.seek(0)
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

    f = open(filepath, "r", encoding="utf-8", errors="replace")
    raw_text = f.read().replace("\x00", "")
    f.close()
    clean_stream = io.StringIO(raw_text)
    reader = csv.DictReader(clean_stream)
    return reader, clean_stream


def parse_timestamp(ts_str: str) -> str:
    """Normalize deletion timestamp into ISO format (YYYY-MM-DD HH:MM:SS) in UTC or return original."""
    if not ts_str or not ts_str.strip():
        return ""
    ts_str = ts_str.strip()

    # Support Unix epoch timestamp
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


def parse_recycle(path: str) -> List[Dict[str, str]]:
    """Parse a Recycle Bin export CSV into normalized records."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Recycle CSV file not found: {path}")

    reader, f = open_csv_multienconding(path)
    rows = []
    try:
        for idx, r in enumerate(reader, start=1):
            if not r or all(v is None or v == "" for v in r.values()):
                continue

            recycle_name = get_field_insensitive(r, ["RecycleName", "Recycle Name", "ArtifactName", "TempName", "FileName_Recycled"])
            filename = get_field_insensitive(r, ["FileName", "Filename", "OriginalName", "Name", "Original Filename"])
            orig_path = get_field_insensitive(r, ["OriginalPath", "Original Path", "Path", "Directory", "Folder"])
            deletion_time = parse_timestamp(
                get_field_insensitive(r, ["DeletionTime", "DeletedTime", "Deleted", "DateDeleted", "Timestamp"])
            )
            size = get_field_insensitive(r, ["Size", "FileSize", "OriginalSize", "Bytes"])

            rows.append({
                "recycle_name": recycle_name or f"$R_{idx}",
                "filename": filename,
                "original_path": orig_path,
                "deleted": deletion_time,
                "size": size,
            })
    finally:
        f.close()

    logger.info("Successfully parsed %d Recycle Bin records from %s", len(rows), path)
    return rows


def write_reports(rows: List[Dict[str, str]], basedir: str = None, report_out: str = None, timeline_out: str = None) -> Tuple[str, str]:
    """Generate both a normalized Recycle Bin report and a timeline CSV."""
    if not basedir:
        basedir = "."

    rep_path = report_out or os.path.join(basedir, "recycle_report.csv")
    tl_path = timeline_out or os.path.join(basedir, "recycle_timeline.csv")

    headers = ["recycle_name", "filename", "original_path", "deleted", "size"]
    with open(rep_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in headers})
    logger.info("Recycle Bin report written to: %s", rep_path)

    tl_headers = ["timestamp", "source_artifact", "event", "filename", "size", "original_path", "recycle_name"]
    with open(tl_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=tl_headers)
        writer.writeheader()
        for r in rows:
            if r.get("deleted"):
                writer.writerow({
                    "timestamp": r["deleted"],
                    "source_artifact": "RecycleBin",
                    "event": "deleted",
                    "filename": r.get("filename", ""),
                    "size": r.get("size", ""),
                    "original_path": r.get("original_path", ""),
                    "recycle_name": r.get("recycle_name", ""),
                })
    logger.info("Recycle Bin timeline written to: %s", tl_path)

    return rep_path, tl_path


def main():
    parser = argparse.ArgumentParser(
        description="Windows Recycle Bin CSV Parser — Parse deletion events and reconstruct timelines."
    )
    parser.add_argument("recycle_csv", help="Path to exported Recycle Bin CSV file")
    parser.add_argument("-o", "--outdir", default=None, help="Output directory for generated reports")
    parser.add_argument("--report", default=None, help="Custom output path for recycle_report.csv")
    parser.add_argument("--timeline", default=None, help="Custom output path for recycle_timeline.csv")

    args = parser.parse_args()

    base_dir = args.outdir
    if not base_dir:
        base_dir = os.path.dirname(args.recycle_csv) or "."

    rows = parse_recycle(args.recycle_csv)
    write_reports(rows, basedir=base_dir, report_out=args.report, timeline_out=args.timeline)


if __name__ == "__main__":
    main()
