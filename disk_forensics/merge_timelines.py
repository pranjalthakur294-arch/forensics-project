"""
merge_timelines.py (fixed)
Merge CSV timelines (mft_timeline.csv + recycle_timeline.csv) into timeline_merged.csv
Handles differing headers by taking the union of all fieldnames and filling missing values.
Usage:
  python merge_timelines.py mft_timeline.csv recycle_timeline.csv timeline_merged.csv
"""
import csv
import sys
from datetime import datetime

def read_rows(path):
    rows = []
    headers = []
    try:
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            r = csv.DictReader(f)
            headers = r.fieldnames or []
            for row in r:
                rows.append(dict(row))  # make a plain dict copy
    except FileNotFoundError:
        print(f"Warning: file not found: {path} -- continuing with empty list")
    return rows, headers

def try_parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        # best-effort: try common formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                continue
    return None

def main():
    if len(sys.argv) < 4:
        print("Usage: python merge_timelines.py mft_timeline.csv recycle_timeline.csv timeline_merged.csv")
        sys.exit(1)

    path_a = sys.argv[1]
    path_b = sys.argv[2]
    out_path = sys.argv[3]

    a_rows, a_hdrs = read_rows(path_a)
    b_rows, b_hdrs = read_rows(path_b)

    combined = a_rows + b_rows

    if not combined:
        print("No rows found in input files. Exiting.")
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            f.write("")  # write empty file
        print("Wrote empty file:", out_path)
        return

    # union of all fieldnames
    all_fieldnames = []
    for hdr_list in (a_hdrs or []) + (b_hdrs or []):
        if hdr_list:
            for h in hdr_list:
                if h not in all_fieldnames:
                    all_fieldnames.append(h)
    # fallback: if fieldnames empty, get keys from rows
    if not all_fieldnames:
        for row in combined:
            for k in row.keys():
                if k not in all_fieldnames:
                    all_fieldnames.append(k)

    # ensure 'timestamp' is first column if present (makes reading easier)
    if 'timestamp' in all_fieldnames:
        all_fieldnames = ['timestamp'] + [f for f in all_fieldnames if f != 'timestamp']

    # sort combined by timestamp where possible, otherwise lexicographic
    def sort_key(row):
        t = try_parse_iso(row.get('timestamp',''))
        return (t or row.get('timestamp',''))
    combined.sort(key=sort_key)

    # write with full union of headers, filling missing fields with ''
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames)
        writer.writeheader()
        for row in combined:
            out_row = {k: (row.get(k) if row.get(k) is not None else '') for k in all_fieldnames}
            writer.writerow(out_row)

    print("Wrote merged timeline to", out_path)

if __name__ == "__main__":
    main()
