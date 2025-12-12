"""
Recycle Bin CSV parser
"""

import csv
import sys
import os
from dateutil import parser as dparser

def ts(s):
    if not s: return ""
    try: return dparser.parse(s).isoformat(" ")
    except: return s

def parse_recycle(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "recycle_name": r.get("RecycleName",""),
                "filename": r.get("FileName",""),
                "original_path": r.get("OriginalPath",""),
                "deleted": ts(r.get("DeletionTime","")),
                "size": r.get("Size","")
            })
    return rows

def write_reports(rows, basedir):
    rep = os.path.join(basedir, "recycle_report.csv")
    with open(rep, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["recycle_name","filename","original_path","deleted","size"])
        for r in rows:
            w.writerow([r[k] for k in ["recycle_name","filename","original_path","deleted","size"]])
    print("Wrote:", rep)

    tl = os.path.join(basedir, "recycle_timeline.csv")
    with open(tl, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp","event","filename","original_path","recycle_name"])
        for r in rows:
            if r["deleted"]:
                w.writerow([r["deleted"], "deleted", r["filename"], r["original_path"], r["recycle_name"]])
    print("Wrote:", tl)

def main():
    if len(sys.argv) < 2:
        print("Usage: python recycle_parser.py exported_recycle.csv")
        sys.exit(0)

    path = sys.argv[1]
    rows = parse_recycle(path)
    write_reports(rows, os.path.dirname(path))

if __name__=="__main__":
    main()
