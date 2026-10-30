"""
pcap_analyze_extended.py - Extended Forensic PCAP Analysis & Timeline Generator
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Deep packet inspection with dual IPv4 and IPv6 support
- Protocol distribution metrics
- Top communicating IP addresses & conversation pairs
- Port distribution (TCP and UDP)
- Extracted DNS queries
- Generates chronological packet timeline CSV (timestamp, src, dst, proto, len, info)
- Generates SHA-256 forensic evidence metadata file (*.evidence.txt) for chain of custody
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, ICMP, ARP
except ImportError:
    sys.exit("Error: Scapy is required. Install it using: pip install scapy")

CHUNK_SIZE = 64 * 1024


def identify_protocol(p) -> str:
    """Accurately identify packet protocol beyond payload names."""
    if TCP in p:
        return "TCP"
    if UDP in p:
        return "UDP"
    if ICMP in p:
        return "ICMP"
    if p.haslayer("ICMPv6EchoRequest") or p.haslayer("ICMPv6EchoReply") or p.haslayer("ICMPv6"):
        return "ICMPv6"
    if ARP in p:
        return "ARP"
    if IP in p:
        return f"IPv4-Proto-{p[IP].proto}"
    if IPv6 in p:
        return f"IPv6-NH-{p[IPv6].nh}"
    return p.name


def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 digest of a PCAP file in streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def analyze_extended(
    pcap_path: str,
    timeline_path: str = None,
    evidence_path: str = None,
    top_n: int = 10,
) -> Dict:
    """Perform extended forensic PCAP inspection, export timeline CSV, and generate evidence report."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    pkts = rdpcap(pcap_path)
    total_packets = len(pkts)
    print(f"[+] Loaded {total_packets} packets from: {pcap_path}\n")

    ips = Counter()
    conversation_pairs = Counter()
    ports = Counter()
    protocols = Counter()
    dns_queries: List[str] = []
    timeline_rows: List[Tuple[str, str, str, str, int, str]] = []

    first_ts = None
    last_ts = None

    for p in pkts:
        pkt_time = float(p.time)
        ts_str = datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S")
        if first_ts is None:
            first_ts = ts_str
        last_ts = ts_str

        length = len(p)
        proto = identify_protocol(p)
        protocols[proto] += 1

        src = ""
        dst = ""
        info = ""

        # Handle both IPv4 and IPv6
        if IP in p:
            src = p[IP].src
            dst = p[IP].dst
            ips[src] += 1
            ips[dst] += 1
            conversation_pairs[tuple(sorted([src, dst]))] += 1
        elif IPv6 in p:
            src = p[IPv6].src
            dst = p[IPv6].dst
            ips[src] += 1
            ips[dst] += 1
            conversation_pairs[tuple(sorted([src, dst]))] += 1

        # Protocol & Transport Layer Details
        if TCP in p:
            sport = p[TCP].sport
            dport = p[TCP].dport
            ports[sport] += 1
            ports[dport] += 1
            info = f"TCP {sport} -> {dport} [Flags: {p[TCP].flags}]"

            # HTTP heuristic extraction on ports 80/8080 or raw payload
            if dport in (80, 8080) or sport in (80, 8080):
                try:
                    raw = bytes(p[TCP].payload)
                    if raw:
                        first_line = raw[:150].decode("utf-8", errors="replace").split("\r\n")[0]
                        info += f" | HTTP: {first_line}"
                except Exception:
                    pass

        elif UDP in p:
            sport = p[UDP].sport
            dport = p[UDP].dport
            ports[sport] += 1
            ports[dport] += 1
            info = f"UDP {sport} -> {dport}"

            # DNS Query extraction
            if p.haslayer(DNS):
                dns_layer = p.getlayer(DNS)
                qd = getattr(dns_layer, "qd", None)
                if qd:
                    try:
                        first_q = qd[0] if isinstance(qd, list) else qd
                        qname = first_q.qname.decode("utf-8", errors="replace").rstrip(".")
                        if qname and qname not in dns_queries:
                            dns_queries.append(qname)
                        info += f" | DNS Q: {qname}"
                    except Exception:
                        pass
        else:
            info = proto

        timeline_rows.append((ts_str, src, dst, proto, length, info))

    # Print summary statistics
    print(f"--- Capture Overview ---")
    print(f"  Total Packets:   {total_packets}")
    print(f"  First Packet:    {first_ts or 'N/A'}")
    print(f"  Last Packet:     {last_ts or 'N/A'}")

    print(f"\n--- Protocol Distribution ---")
    for pr, count in protocols.most_common():
        pct = (count / total_packets) * 100 if total_packets else 0
        print(f"  {pr:<8}: {count:>5} packets ({pct:.1f}%)")

    print(f"\n--- Top {top_n} Communicating IP Addresses ---")
    for ip, count in ips.most_common(top_n):
        print(f"  {ip:<42} -> {count:>4} packets")

    print(f"\n--- Top Communicating Conversations (IP Pairs) ---")
    for pair, count in conversation_pairs.most_common(top_n):
        print(f"  {pair[0]} <---> {pair[1]} : {count} packets")

    print(f"\n--- Top {top_n} Transport Ports (TCP/UDP) ---")
    for port, count in ports.most_common(top_n):
        print(f"  Port {port:<6} -> {count:>4} hits")

    print(f"\n--- DNS Queries Identified ({len(dns_queries)} unique) ---")
    for q in dns_queries[:top_n]:
        print(f"  Query: {q}")

    # Write Timeline CSV
    if not timeline_path:
        timeline_path = os.path.splitext(pcap_path)[0] + "_timeline.csv"
    with open(timeline_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["timestamp", "src", "dst", "proto", "length", "info"])
        for row in timeline_rows:
            writer.writerow(row)
    print(f"\n[+] Timeline CSV written to: {timeline_path}")

    # Write Evidence Report
    sha256_hash = compute_sha256(pcap_path)
    file_size = os.path.getsize(pcap_path)
    if not evidence_path:
        evidence_path = pcap_path + ".evidence.txt"

    with open(evidence_path, "w", encoding="utf-8") as ef:
        ef.write("=== Forensic Evidence Custody Report ===\n")
        ef.write(f"pcap_file: {os.path.basename(pcap_path)}\n")
        ef.write(f"full_path: {os.path.abspath(pcap_path)}\n")
        ef.write(f"pcap_sha256: {sha256_hash}\n")
        ef.write(f"file_size_bytes: {file_size}\n")
        ef.write(f"total_packets: {total_packets}\n")
        ef.write(f"capture_start: {first_ts or 'N/A'}\n")
        ef.write(f"capture_end: {last_ts or 'N/A'}\n")
        ef.write(f"analyzed_utc: {datetime.now(timezone.utc).isoformat()}\n")
        ef.write("generator: pcap_analyze_extended.py\n")

    print(f"[+] Evidence file written to: {evidence_path}")
    print(f"    PCAP SHA-256: {sha256_hash}")

    return {
        "pcap_sha256": sha256_hash,
        "total_packets": total_packets,
        "protocols": dict(protocols),
        "top_ips": ips.most_common(top_n),
        "dns_queries": dns_queries,
        "timeline_file": timeline_path,
        "evidence_file": evidence_path,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extended Forensic PCAP Analyzer — Timeline Generation & Evidence Hashing"
    )
    parser.add_argument("pcap", help="Path to PCAP capture file")
    parser.add_argument("-t", "--timeline", help="Custom output path for timeline CSV")
    parser.add_argument("-e", "--evidence", help="Custom output path for .evidence.txt file")
    parser.add_argument("-n", "--top", type=int, default=10, help="Number of top entries to display (default: 10)")

    args = parser.parse_args()
    analyze_extended(args.pcap, timeline_path=args.timeline, evidence_path=args.evidence, top_n=args.top)


if __name__ == "__main__":
    main()
