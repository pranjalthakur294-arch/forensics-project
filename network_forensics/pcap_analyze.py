"""
pcap_analyze.py - Baseline Forensic PCAP Packet Analysis Tool
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Rapid triage of PCAP/PCAPNG network captures
- Parses both IPv4 and IPv6 traffic
- Protocol distribution summary
- Top communicating source and destination IP addresses
- Port distribution (TCP/UDP)
- Extracted DNS queries
"""

import argparse
import sys
from collections import Counter
from typing import Dict, List

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, ICMP, ARP
except ImportError:
    sys.exit("Error: Scapy is required. Install it using: pip install scapy")


def identify_protocol(p) -> str:
    """Identify accurate network and transport protocols beyond generic 'Raw' payloads."""
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


def analyze_pcap(path: str, top_n: int = 10) -> Dict:
    """Analyze PCAP file and print baseline forensic statistics."""
    try:
        pkts = rdpcap(path)
    except Exception as e:
        sys.exit(f"Error loading PCAP file '{path}': {e}")

    total_packets = len(pkts)
    print(f"[+] Loaded {total_packets} packets from: {path}\n")

    ips = Counter()
    ports = Counter()
    protocols = Counter()
    dns_queries: List[str] = []

    for p in pkts:
        # Protocol breakdown
        proto = identify_protocol(p)
        protocols[proto] += 1

        if TCP in p:
            ports[p[TCP].sport] += 1
            ports[p[TCP].dport] += 1
        elif UDP in p:
            ports[p[UDP].sport] += 1
            ports[p[UDP].dport] += 1

        # IP addresses (both IPv4 and IPv6)
        if IP in p:
            ips[p[IP].src] += 1
            ips[p[IP].dst] += 1
        elif IPv6 in p:
            ips[p[IPv6].src] += 1
            ips[p[IPv6].dst] += 1

        # DNS queries (with trailing dot normalized)
        if p.haslayer(DNS):
            dns_layer = p.getlayer(DNS)
            qd = getattr(dns_layer, "qd", None)
            if qd:
                try:
                    first_q = qd[0] if isinstance(qd, list) else qd
                    qname = first_q.qname.decode("utf-8", errors="replace").rstrip(".")
                    if qname and qname not in dns_queries:
                        dns_queries.append(qname)
                except Exception:
                    pass

    # Print summaries
    print(f"--- Protocol Distribution ({total_packets} packets) ---")
    for pr, count in protocols.most_common():
        pct = (count / total_packets) * 100 if total_packets else 0
        print(f"  {pr:<8}: {count:>5} packets ({pct:.1f}%)")

    print(f"\n--- Top {top_n} Communicating IP Addresses (IPv4 & IPv6) ---")
    for ip, c in ips.most_common(top_n):
        print(f"  {ip:<42} -> {c:>4} occurrences")

    print(f"\n--- Top {top_n} Ports (TCP/UDP) ---")
    for port, c in ports.most_common(top_n):
        print(f"  Port {port:<6} -> {c:>4} hits")

    print(f"\n--- DNS Queries Identified ({len(dns_queries)} unique) ---")
    for q in dns_queries[:top_n]:
        print(f"  Query: {q}")

    return {
        "total_packets": total_packets,
        "protocols": dict(protocols),
        "top_ips": ips.most_common(top_n),
        "top_ports": ports.most_common(top_n),
        "dns_queries": dns_queries,
    }


def main():
    parser = argparse.ArgumentParser(description="Baseline Forensic PCAP Analysis (IPv4/IPv6, Protocols, DNS)")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("-n", "--top", type=int, default=10, help="Number of top entries to display (default: 10)")
    args = parser.parse_args()

    analyze_pcap(args.pcap, top_n=args.top)


if __name__ == "__main__":
    main()
