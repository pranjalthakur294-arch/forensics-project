"""
mft_parser.py - CSV-based MFT parser
"""

import csv
from dateutil import parser as dparser
from collections import Counter
import sys
import os

def parse_timestamp(ts):
    if not ts: 
        return ""
    try:
        return dparser.parse(ts).isoformat(" ")
    except:
        return ts

def is_deleted(flags, inuse):
    if inuse and inuse.strip() in ("0", "False", "false"):
        return True
    if flags and "deleted" in flags.lower():
        return True
    return False

def parse_mft(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for r in reader:
            fn = r.get("Filename") or r.get("Name") or ""
            full = r.get("FullPath") or r.get("Path") or ""
            flags = r.get("EntryFlags") or ""
            inuse = r.get("InUse") or ""
            rows.append({
                "record": r.get("RecordNumber",""),
                "filename": fn,
                "fullpath": full,
                "created": parse_timestamp(r.get("Created","")),
                "modified": parse_timestamp(r.get("Modified","")),
                "accessed": parse_timestamp(r.get("Accessed","")),
                "flags": flags,
                "inuse": inuse,
                "deleted": is_deleted(flags, inuse)
            })
    return rows

def write_reports(rows, basedir):
    rep = os.path.join(basedir, "mft_report.csv")
    with open(rep, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["record","filename","fullpath","created","modified","accessed","flags","inuse","deleted"])
        for r in rows:
            w.writerow([r[k] for k in ["record","filename","fullpath","created","modified","accessed","flags","inuse","deleted"]])
    print("Wrote:", rep)

    tl = os.path.join(basedir, "mft_timeline.csv")
    with open(tl, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp","event","filename","fullpath","flags","deleted"])
        for r in rows:
            for label in ("created","modified","accessed"):
                ts = r[label]
                if ts:
                    w.writerow([ts, label, r["filename"], r["fullpath"], r["flags"], r["deleted"]])
    print("Wrote:", tl)

def main():
    if len(sys.argv) < 2:
        print("Usage: python mft_parser.py exported_mft.csv")
        sys.exit(0)

    path = sys.argv[1]
    rows = parse_mft(path)
    print("Total records:", len(rows))
    write_reports(rows, os.path.dirname(path))

if __name__=="__main__":
    main()
