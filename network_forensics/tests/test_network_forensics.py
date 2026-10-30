"""
test_network_forensics.py - Automated Unit & Integration Tests for Network Forensics Module (Hardened)
Tests:
- PCAP parsing (IPv4 & IPv6 address accounting, protocol breakdown)
- DNS query extraction and trailing dot normalization
- Extended timeline CSV and SHA-256 evidence generation
- Multi-segment TCP stream reassembly for HTTP requests
- Multi-segment TLS ClientHello SNI extraction
- Protocol classification (TCP, UDP, ICMP, ARP, ICMPv6)
- Forensic engine comparison (TShark vs Scapy fallback)
- Network interface enumeration
"""

import os
import sys
import unittest
import tempfile
import shutil
import csv

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
NET_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if NET_DIR not in sys.path:
    sys.path.insert(0, NET_DIR)

from scapy.all import Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, ICMP, ARP, Raw, wrpcap

from pcap_analyze import analyze_pcap
from pcap_analyze_extended import analyze_extended, compute_sha256
from pyshark_http_tls import extract_with_scapy, extract_http_tls, compare_engines
from wifi_sniffer import list_network_interfaces


class TestNetworkForensics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="forensics_net_test_")
        self.pcap_path = os.path.join(self.test_dir, "synthetic_test.pcap")

        # 1. Packet 1: HTTP GET request (IPv4 + TCP)
        http_payload = b"GET /admin/dashboard.php HTTP/1.1\r\nHost: corporate-intranet.local\r\nUser-Agent: TestAgent\r\n\r\n"
        pkt1 = Ether() / IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=49152, dport=80, seq=100) / http_payload

        # 2. Packet 2: DNS Query (IPv6 + UDP)
        pkt2 = Ether() / IPv6(src="2001:db8::1", dst="2001:4860:4860::8888") / UDP(sport=53535, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="suspicious-domain.test")
        )

        # 3. Packet 3: TLS ClientHello with SNI "secure.payments-portal.com"
        sni_host = b"secure.payments-portal.com"
        sni_entry = b"\x00" + bytes([0, len(sni_host)]) + sni_host
        sni_list = bytes([0, len(sni_entry)]) + sni_entry
        ext_sni = b"\x00\x00" + bytes([0, len(sni_list)]) + sni_list
        extensions = ext_sni
        ext_total_len = len(extensions)

        client_hello = (
            b"\x01\x00" + bytes([0, 38 + ext_total_len])  # Handshake type + length
            + b"\x03\x03"                                  # Client version
            + (b"\x11" * 32)                               # Random 32 bytes
            + b"\x00"                                      # Session ID length 0
            + b"\x00\x02\x00\x2f"                          # Cipher Suites length 2, TLS_RSA_WITH_AES_128_CBC_SHA
            + b"\x01\x00"                                  # Compression length 1, null
            + bytes([ext_total_len >> 8, ext_total_len & 0xFF]) + extensions
        )
        tls_record = b"\x16\x03\x01" + bytes([len(client_hello) >> 8, len(client_hello) & 0xFF]) + client_hello
        pkt3 = Ether() / IP(src="192.168.1.50", dst="104.21.5.12") / TCP(sport=51234, dport=443, seq=200) / tls_record

        # Save synthetic PCAP
        wrpcap(self.pcap_path, [pkt1, pkt2, pkt3])

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_baseline_pcap_analyze(self):
        """Verify pcap_analyze identifies IPv4, IPv6, ports, and DNS queries."""
        res = analyze_pcap(self.pcap_path)
        self.assertEqual(res["total_packets"], 3)
        self.assertIn("TCP", res["protocols"])
        self.assertIn("UDP", res["protocols"])
        self.assertIn("suspicious-domain.test", res["dns_queries"])

        top_ips = [ip for ip, _ in res["top_ips"]]
        self.assertIn("192.168.1.50", top_ips)
        self.assertIn("2001:db8::1", top_ips)

    def test_pcap_analyze_extended_evidence_and_timeline(self):
        """Verify pcap_analyze_extended creates valid timeline CSV and evidence report."""
        timeline_out = os.path.join(self.test_dir, "timeline.csv")
        evidence_out = os.path.join(self.test_dir, "evidence.txt")

        res = analyze_extended(
            self.pcap_path,
            timeline_path=timeline_out,
            evidence_path=evidence_out,
        )

        self.assertEqual(res["total_packets"], 3)
        self.assertTrue(os.path.exists(timeline_out))
        self.assertTrue(os.path.exists(evidence_out))

        computed_sha = compute_sha256(self.pcap_path)
        self.assertEqual(res["pcap_sha256"], computed_sha)

        with open(evidence_out, "r", encoding="utf-8") as ef:
            content = ef.read()
            self.assertIn(computed_sha, content)
            self.assertIn("total_packets: 3", content)

        with open(timeline_out, "r", encoding="utf-8") as tf:
            reader = csv.DictReader(tf)
            rows = list(reader)
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["src"], "192.168.1.50")
            self.assertEqual(rows[1]["src"], "2001:db8::1")

    def test_multi_segment_tcp_http_reassembly(self):
        """Verify Scapy stateful stream reassembly on an HTTP request split across 2 packets."""
        multi_pcap = os.path.join(self.test_dir, "multiseg_http.pcap")
        # Packet 1 contains request line
        p1 = Ether() / IP(src="10.0.0.5", dst="10.0.0.8") / TCP(sport=50001, dport=80, seq=1000) / b"GET /api/v2/telemetry HTTP/1.1\r\n"
        # Packet 2 contains headers and terminator
        p2 = Ether() / IP(src="10.0.0.5", dst="10.0.0.8") / TCP(sport=50001, dport=80, seq=1032) / b"Host: multi-segment.org\r\nAccept: */*\r\n\r\n"
        wrpcap(multi_pcap, [p1, p2])

        rows = extract_with_scapy(multi_pcap)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "multi-segment.org")
        self.assertEqual(rows[0][2], "/api/v2/telemetry")

    def test_multi_segment_tls_client_hello(self):
        """Verify TLS ClientHello extraction when split across 2 packets."""
        multi_tls_pcap = os.path.join(self.test_dir, "multiseg_tls.pcap")

        sni_host = b"split-stream.portal.net"
        sni_entry = b"\x00" + bytes([0, len(sni_host)]) + sni_host
        sni_list = bytes([0, len(sni_entry)]) + sni_entry
        ext_sni = b"\x00\x00" + bytes([0, len(sni_list)]) + sni_list
        ext_total_len = len(ext_sni)

        client_hello = (
            b"\x01\x00" + bytes([0, 38 + ext_total_len])
            + b"\x03\x03"
            + (b"\x22" * 32)
            + b"\x00"
            + b"\x00\x02\x00\x2f"
            + b"\x01\x00"
            + bytes([ext_total_len >> 8, ext_total_len & 0xFF]) + ext_sni
        )
        full_record = b"\x16\x03\x01" + bytes([len(client_hello) >> 8, len(client_hello) & 0xFF]) + client_hello

        # Split at index 25
        part1 = full_record[:25]
        part2 = full_record[25:]

        p1 = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50002, dport=443, seq=2000) / part1
        p2 = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50002, dport=443, seq=2025) / part2
        wrpcap(multi_tls_pcap, [p1, p2])

        rows = extract_with_scapy(multi_tls_pcap)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], "split-stream.portal.net")

    def test_icmp_and_arp_protocol_identification(self):
        """Verify ICMP and ARP packets are accurately identified instead of being lumped into 'Raw'."""
        icmp_pkt = Ether() / IP(src="10.10.10.1", dst="10.10.10.2") / ICMP() / Raw(b"pingdata")
        arp_pkt = Ether() / ARP(psrc="10.10.10.1", pdst="10.10.10.2")

        icmp_pcap = os.path.join(self.test_dir, "icmp_arp.pcap")
        wrpcap(icmp_pcap, [icmp_pkt, arp_pkt])

        res = analyze_pcap(icmp_pcap)
        self.assertIn("ICMP", res["protocols"])
        self.assertIn("ARP", res["protocols"])
        self.assertNotIn("Raw", res["protocols"])

    def test_engine_comparison_runs(self):
        """Verify forensic compare_engines executes cleanly against sample PCAP."""
        summary = compare_engines(self.pcap_path)
        self.assertIsInstance(summary, dict)
        self.assertIn("scapy_count", summary)
        self.assertGreaterEqual(summary["scapy_count"], 1)

    def test_nonexistent_pcap_raises_error(self):
        """Verify non-existent PCAP raises FileNotFoundError in analyze_extended."""
        with self.assertRaises(FileNotFoundError):
            analyze_extended("nonexistent_capture_file.pcap")

    def test_wifi_interface_enumeration(self):
        """Verify interface discovery does not throw unexpected exceptions."""
        interfaces = list_network_interfaces()
        self.assertIsInstance(interfaces, list)


if __name__ == "__main__":
    unittest.main()
