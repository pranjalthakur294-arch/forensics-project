"""
merge_timelines.py - Forensic Timeline Merging & Normalization Engine
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Ingests multiple timeline CSVs (e.g., MFT timeline, Recycle Bin timeline, Web history)
- Reconciles heterogeneous schemas using an ordered union of all observed column headers
- Normalizes missing fields cleanly without data corruption
- Strictly sorts events in chronological order (handling ISO-8601 timestamps and unparseable edge cases safely)
- Produces a unified master timeline for timeline analysis in forensic investigations
"""

import argparse
import csv
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("merge_timelines")


def read_timeline_csv(path: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """Read a timeline CSV file and return (rows, headers)."""
    rows = []
    headers = []
    if not os.path.exists(path):
        logger.warning("Timeline input file not found: %s (skipping)", path)
        return rows, headers

    encodings_to_try = ["utf-8-sig", "utf-16", "cp1252", "latin-1"]
    for enc in encodings_to_try:
        try:
            with open(path, "r", newline="", encoding=enc, errors="strict") as f:
                sample = f.read(2048)
                f.seek(0)
                r = csv.DictReader(f)
                headers = [h.strip() for h in (r.fieldnames or []) if h]
                for row in r:
                    rows.append({k.strip(): (v.strip() if v else "") for k, v in row.items() if k})
                return rows, headers
        except (UnicodeError, csv.Error):
            continue

    # Fallback
    with open(path, "r", newline="", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        headers = [h.strip() for h in (r.fieldnames or []) if h]
        for row in r:
            rows.append({k.strip(): (v.strip() if v else "") for k, v in row.items() if k})

    return rows, headers


def parse_timestamp_safe(s: Optional[str]) -> Optional[datetime]:
    """Attempt parsing an ISO timestamp or common forensic datetime formats."""
    if not s or not s.strip():
        return None
    s = s.strip()
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


def merge_and_sort_timelines(timeline_files: List[str], output_path: str) -> int:
    """
    Merge multiple timeline CSV files into a unified chronological master timeline.
    Returns the total number of events written.
    """
    combined_rows: List[Dict[str, str]] = []
    all_headers: List[str] = []

    # Read each timeline file
    for path in timeline_files:
        rows, hdrs = read_timeline_csv(path)
        logger.info("Loaded %d events from %s", len(rows), path)
        combined_rows.extend(rows)

        # Build union of headers preserving first appearance order
        for h in hdrs:
            if h and h not in all_headers:
                all_headers.append(h)

    # Fallback header extraction if headers were missing
    if not all_headers:
        for row in combined_rows:
            for k in row.keys():
                if k and k not in all_headers:
                    all_headers.append(k)

    if not combined_rows:
        logger.warning("No rows found in any provided timeline file.")
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write("")
        return 0

    # Ensure key forensic columns appear first in standardized order
    preferred_order = ["timestamp", "source_artifact", "event", "filename", "record", "size", "fullpath", "original_path", "recycle_name", "flags", "deleted"]
    ordered_headers: List[str] = []
    for col in preferred_order:
        if col in all_headers:
            ordered_headers.append(col)
    for col in all_headers:
        if col not in ordered_headers:
            ordered_headers.append(col)

    # Deduplicate exact duplicate event records while preserving chronological order
    unique_rows = []
    seen = set()
    for r in combined_rows:
        key = tuple(r.get(k, "") for k in ordered_headers)
        if key not in seen:
            seen.add(key)
            unique_rows.append(r)
    if len(combined_rows) != len(unique_rows):
        logger.info("Deduplicated %d duplicate events (%d unique remain)", len(combined_rows) - len(unique_rows), len(unique_rows))
    combined_rows = unique_rows

    # Sort rows chronologically: valid timestamps first (earliest to latest), unparseable/empty at end
    def sort_key(row: Dict[str, str]):
        ts_val = row.get("timestamp", "")
        parsed = parse_timestamp_safe(ts_val)
        if parsed is not None:
            return (0, parsed, ts_val)
        return (1, datetime.max, ts_val or "")

    combined_rows.sort(key=sort_key)

    # Write merged timeline
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_headers)
        writer.writeheader()
        for r in combined_rows:
            clean_row = {k: r.get(k, "") for k in ordered_headers}
            writer.writerow(clean_row)

    logger.info("Wrote %d chronological events to: %s", len(combined_rows), output_path)
    return len(combined_rows)


def main():
    parser = argparse.ArgumentParser(
        description="Merge heterogeneous forensic timeline CSVs into a single chronological timeline."
    )
    parser.add_argument("timelines", nargs="+", help="Paths to timeline CSV files to merge")
    parser.add_argument("-o", "--output", required=True, help="Destination path for merged master timeline")

    args = parser.parse_args()
    merge_and_sort_timelines(args.timelines, args.output)


if __name__ == "__main__":
    main()
