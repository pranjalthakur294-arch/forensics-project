# pcap_analyze_extended.py
"""
Extended PCAP analyzer (Scapy)
- Loads a pcap
- Prints top IPs and ports
- Extracts DNS queries
- Builds a timeline CSV (timestamp, src, dst, proto, len, info)
- Computes SHA256 of the PCAP and writes an evidence file
Usage:
  python pcap_analyze_extended.py test_capture.pcap
Produces:
  - timeline.csv
  - <pcap>.evidence.txt
"""

import sys, os, csv, hashlib
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter
from datetime import datetime

CHUNK = 8192

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.hexdigest()

def analyze(pcap_path):
    pkts = rdpcap(pcap_path)
    print(f"Loaded {len(pkts)} packets\n")

    ips = Counter()
    ports = Counter()
    dns_queries = []
    timeline_rows = []

    for p in pkts:
        ts = datetime.fromtimestamp(float(p.time)).isoformat(sep=' ')
        length = len(p)
        proto = p.lastlayer().name if p.lastlayer() is not None else "UNK"

        src = dst = ""
        info = ""

        if IP in p:
            src = p[IP].src
            dst = p[IP].dst
            ips[src] += 1
            ips[dst] += 0

        if TCP in p:
            sport = p[TCP].sport
            dport = p[TCP].dport
            ports[sport] += 1
            ports[dport] += 1
            info = f"TCP {sport}->{dport}"
            # attempt to get HTTP payload heuristically (port 80)
            if dport == 80 or sport == 80:
                try:
                    raw = bytes(p[TCP].payload)
                    if raw:
                        # show start of payload (utf-8 best-effort)
                        snippet = raw[:200].decode('utf-8', errors='replace').replace('\n',' ').replace('\r',' ')
                        info += " | " + snippet
                except Exception:
                    pass
        elif UDP in p:
            sport = p[UDP].sport
            dport = p[UDP].dport
            ports[sport] += 1
            ports[dport] += 1
            info = f"UDP {sport}->{dport}"
            # DNS
            if p.haslayer(DNS) and p.getlayer(DNS).qd:
                try:
                    q = p.getlayer(DNS).qd.qname.decode()
                    dns_queries.append(q)
                    info += f" | DNS q: {q}"
                except:
                    pass
        else:
            info = proto

        timeline_rows.append((ts, src, dst, proto, length, info))

    # Print summaries
    print("Top IPs:")
    for ip, c in ips.most_common(10):
        print(f"  {ip} -> {c}")

    print("\nTop Ports:")
    for port, c in ports.most_common(10):
        print(f"  {port} -> {c}")

    print("\nDNS Queries (sample):")
    for q in dns_queries[:20]:
        print(" ", q)

    # Write timeline CSV
    csv_path = os.path.splitext(pcap_path)[0] + "_timeline.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["timestamp","src","dst","proto","length","info"])
        for row in timeline_rows:
            writer.writerow(row)
    print(f"\nTimeline CSV written: {csv_path}")

    # Write evidence file with SHA256
    sha = sha256_file(pcap_path)
    ev_path = pcap_path + ".evidence.txt"
    with open(ev_path, "w", encoding="utf-8") as ef:
        ef.write("Forensic Evidence Report\n")
        ef.write(f"pcap_file: {pcap_path}\n")
        ef.write(f"pcap_sha256: {sha}\n")
        ef.write(f"packets: {len(pkts)}\n")
        ef.write(f"generated_by: pcap_analyze_extended.py\n")
    print(f"Evidence file written: {ev_path}")
    print(f"PCAP SHA256: {sha}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyze_extended.py <pcapfile>")
        sys.exit(1)
    analyze(sys.argv[1])
