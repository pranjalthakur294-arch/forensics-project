# pcap_analyze.py
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from collections import Counter
import sys

def parse_pcap(path):
    pkts = rdpcap(path)
    print(f"Loaded {len(pkts)} packets\n")

    ips = Counter()
    ports = Counter()
    dns_queries = []

    for p in pkts:
        # IP addresses
        if IP in p:
            ips[p[IP].src] += 1
            ips[p[IP].dst] += 1

        # TCP/UDP ports
        if TCP in p:
            ports[p[TCP].sport] += 1
            ports[p[TCP].dport] += 1
        elif UDP in p:
            ports[p[UDP].sport] += 1
            ports[p[UDP].dport] += 1

        # DNS queries
        if p.haslayer(DNS) and p.getlayer(DNS).qd:
            try:
                q = p.getlayer(DNS).qd.qname.decode()
                dns_queries.append(q)
            except Exception:
                pass

    print("Top IPs:")
    for ip, c in ips.most_common(10):
        print(f"  {ip} -> {c}")

    print("\nTop Ports:")
    for port, c in ports.most_common(10):
        print(f"  {port} -> {c}")

    print("\nDNS Queries (sample):")
    for q in dns_queries[:10]:
        print(" ", q)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyze.py <pcapfile>")
        sys.exit(1)
    parse_pcap(sys.argv[1])
