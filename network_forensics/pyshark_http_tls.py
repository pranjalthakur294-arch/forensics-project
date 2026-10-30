"""
pyshark_http_tls.py - Forensic HTTP and TLS SNI Network Artifact Extractor
Part of the Digital Forensics Portfolio Suite.

Functionality:
- Extracts unencrypted HTTP request metadata (Host headers, URIs)
- Extracts TLS Server Name Indication (SNI) from TLS ClientHello handshakes
- Supports stateful multi-segment TCP stream reassembly in Scapy fallback mode
- Auto-locates TShark on Windows (including default Program Files paths)
- Python 3.12+ / 3.14 asyncio compatibility handling
- Engine comparison tool (TShark vs Scapy fallback) to audit discrepancies
- Exports extracted artifacts to structured CSV for timeline correlation
"""

import argparse
import asyncio
import csv
import os
import shutil
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

# Initialize asyncio event loop for Python 3.12+ / 3.14
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())


def find_tshark_path(custom_path: str = None) -> str:
    """Locate tshark executable in PATH, custom argument, or standard Windows installations."""
    if custom_path and os.path.isfile(custom_path):
        return custom_path

    # Check system PATH
    found = shutil.which("tshark")
    if found:
        return found

    # Common Windows installation directories
    candidate_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for cp in candidate_paths:
        if os.path.isfile(cp):
            return cp

    return None


def extract_with_pyshark(pcap_path: str, tshark_path: str = None) -> List[Tuple[str, str, str, str]]:
    """Extract HTTP and TLS metadata using PyShark."""
    import pyshark

    kwargs = {"use_json": True}
    if tshark_path:
        kwargs["tshark_path"] = tshark_path

    cap = pyshark.FileCapture(pcap_path, **kwargs)
    rows = []
    try:
        for pkt in cap:
            try:
                ts = pkt.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = ""

            http_host = ""
            http_uri = ""
            tls_sni = ""

            # HTTP extraction
            if hasattr(pkt, "http"):
                http = pkt.http
                host_val = getattr(http, "host", None)
                uri_val = getattr(http, "request_uri", None)
                if host_val:
                    http_host = str(host_val)
                if uri_val:
                    http_uri = str(uri_val)

            # TLS SNI extraction
            if hasattr(pkt, "tls"):
                tls = pkt.tls
                sni = getattr(tls, "handshake_extensions_server_name", None)
                if not sni:
                    sni = getattr(tls, "server_name", None)
                if sni:
                    tls_sni = str(sni)

            if http_host or http_uri or tls_sni:
                rows.append((ts, http_host, http_uri, tls_sni))
    finally:
        try:
            cap.close()
        except Exception:
            pass

    return rows


def parse_http_headers(raw_bytes: bytes) -> Tuple[str, str]:
    """Parse HTTP request line and Host header from reassembled stream bytes."""
    http_host = ""
    http_uri = ""
    try:
        lines = raw_bytes.split(b"\r\n")
        req_parts = lines[0].split(b" ")
        if len(req_parts) > 1:
            http_uri = req_parts[1].decode("utf-8", errors="replace")
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                http_host = line.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                break
    except Exception:
        pass
    return http_host, http_uri


def parse_tls_sni(raw_bytes: bytes) -> str:
    """Extract Server Name Indication (SNI) from TLS ClientHello record bytes."""
    tls_sni = ""
    # Verify TLS Handshake (0x16), Version (0x03), Handshake Type ClientHello (0x01)
    if raw_bytes.startswith(b"\x16\x03") and len(raw_bytes) > 43 and raw_bytes[5] == 0x01:
        try:
            idx = 43  # past record header, version, random (32 bytes)
            # Skip session ID
            if idx < len(raw_bytes):
                sess_len = raw_bytes[idx]
                idx += 1 + sess_len
            # Skip cipher suites
            if idx + 2 <= len(raw_bytes):
                cs_len = int.from_bytes(raw_bytes[idx:idx+2], "big")
                idx += 2 + cs_len
            # Skip compression methods
            if idx + 1 <= len(raw_bytes):
                comp_len = raw_bytes[idx]
                idx += 1 + comp_len
            # Extensions total length
            if idx + 2 <= len(raw_bytes):
                ext_total_len = int.from_bytes(raw_bytes[idx:idx+2], "big")
                idx += 2
                ext_end = min(idx + ext_total_len, len(raw_bytes))
                while idx + 4 <= ext_end:
                    ext_type = int.from_bytes(raw_bytes[idx:idx+2], "big")
                    ext_len = int.from_bytes(raw_bytes[idx+2:idx+4], "big")
                    idx += 4
                    if ext_type == 0:  # server_name extension (SNI)
                        # SNI list length (2 bytes), SNI type (1 byte), SNI length (2 bytes)
                        if ext_len > 5 and idx + 5 <= len(raw_bytes):
                            sni_name_len = int.from_bytes(raw_bytes[idx+3:idx+5], "big")
                            sni_bytes = raw_bytes[idx+5:idx+5+sni_name_len]
                            tls_sni = sni_bytes.decode("utf-8", errors="replace")
                        break
                    idx += ext_len
        except Exception:
            pass
    return tls_sni


def extract_with_scapy(pcap_path: str) -> List[Tuple[str, str, str, str]]:
    """
    Fallback extractor using Scapy with stateful TCP stream reassembly.
    Handles both single-segment and multi-segment TCP HTTP and TLS ClientHello handshakes.
    """
    from scapy.all import rdpcap, IP, IPv6, TCP

    pkts = rdpcap(pcap_path)
    rows = []

    # Stream buffers keyed by (src, sport, dst, dport)
    stream_buffers: Dict[tuple, bytearray] = defaultdict(bytearray)
    stream_timestamps: Dict[tuple, str] = {}
    stream_types: Dict[tuple, str] = {}

    HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS ")

    for p in pkts:
        if not TCP in p:
            continue

        src_ip = p[IP].src if IP in p else (p[IPv6].src if IPv6 in p else "")
        dst_ip = p[IP].dst if IP in p else (p[IPv6].dst if IPv6 in p else "")
        sport = p[TCP].sport
        dport = p[TCP].dport
        stream_key = (src_ip, sport, dst_ip, dport)

        ts = datetime.fromtimestamp(float(p.time)).strftime("%Y-%m-%d %H:%M:%S")
        raw = bytes(p[TCP].payload)
        if not raw:
            continue

        # Check if new stream start or continuation
        if stream_key not in stream_types:
            # Check for HTTP method start
            if any(raw.startswith(m) for m in HTTP_METHODS):
                stream_types[stream_key] = "HTTP"
                stream_timestamps[stream_key] = ts
            # Check for TLS ClientHello start
            elif raw.startswith(b"\x16\x03") and len(raw) >= 6 and raw[5] == 0x01:
                stream_types[stream_key] = "TLS"
                stream_timestamps[stream_key] = ts

        # If this stream is being tracked, accumulate payload
        if stream_key in stream_types:
            stream_buffers[stream_key].extend(raw)
            stype = stream_types[stream_key]
            stream_ts = stream_timestamps[stream_key]
            buf = bytes(stream_buffers[stream_key])

            if stype == "HTTP":
                # If headers are complete (contains CRLF CRLF), extract and finalize
                if b"\r\n\r\n" in buf:
                    host, uri = parse_http_headers(buf)
                    if host or uri:
                        rows.append((stream_ts, host, uri, ""))
                    del stream_buffers[stream_key]
                    del stream_types[stream_key]
                    del stream_timestamps[stream_key]

            elif stype == "TLS":
                # TLS record length is in bytes 3:5
                if len(buf) >= 5:
                    record_len = int.from_bytes(buf[3:5], "big") + 5
                    if len(buf) >= record_len:
                        sni = parse_tls_sni(buf)
                        if sni:
                            rows.append((stream_ts, "", "", sni))
                        del stream_buffers[stream_key]
                        del stream_types[stream_key]
                        del stream_timestamps[stream_key]

    # Process any unclosed streams remaining at end of capture
    for stream_key, buf_ba in list(stream_buffers.items()):
        buf = bytes(buf_ba)
        stype = stream_types.get(stream_key)
        stream_ts = stream_timestamps.get(stream_key, "")
        if stype == "HTTP":
            host, uri = parse_http_headers(buf)
            if host or uri:
                rows.append((stream_ts, host, uri, ""))
        elif stype == "TLS":
            sni = parse_tls_sni(buf)
            if sni:
                rows.append((stream_ts, "", "", sni))

    return rows


def extract_http_tls(pcap_path: str, out_csv: str = None, custom_tshark: str = None) -> List[Tuple[str, str, str, str]]:
    """Extract HTTP and TLS metadata with automatic engine selection."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if not out_csv:
        out_csv = os.path.splitext(pcap_path)[0] + "_http_tls_extracted.csv"

    tshark_bin = find_tshark_path(custom_tshark)
    rows = []

    if tshark_bin:
        try:
            print(f"[+] Using TShark engine: {tshark_bin}")
            rows = extract_with_pyshark(pcap_path, tshark_bin)
        except Exception as e:
            print(f"[!] PyShark extraction encountered an issue ({e}). Falling back to Scapy...", file=sys.stderr)
            rows = extract_with_scapy(pcap_path)
    else:
        print("[!] TShark not located in PATH or standard directories. Using Scapy engine.")
        rows = extract_with_scapy(pcap_path)

    # Write output CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "http_host", "http_uri", "tls_sni"])
        for r in rows:
            writer.writerow(r)

    print(f"[+] Extracted {len(rows)} HTTP/TLS records to: {out_csv}")
    return rows


def compare_engines(pcap_path: str, custom_tshark: str = None) -> Dict:
    """
    Forensic comparison tool: runs both TShark (PyShark) and Scapy fallback
    against the same capture file and audits concordance and discrepancies.
    """
    tshark_bin = find_tshark_path(custom_tshark)
    scapy_results = extract_with_scapy(pcap_path)
    pyshark_results = []
    pyshark_error = None

    if tshark_bin:
        try:
            pyshark_results = extract_with_pyshark(pcap_path, tshark_bin)
        except Exception as e:
            pyshark_error = str(e)
    else:
        pyshark_error = "TShark executable not available."

    print("\n--- Forensic Engine Comparison: TShark vs Scapy Fallback ---")
    print(f"  Target PCAP:          {pcap_path}")
    print(f"  Scapy Fallback Rows:  {len(scapy_results)}")
    if pyshark_error:
        print(f"  PyShark/TShark Status: Error ({pyshark_error})")
    else:
        print(f"  PyShark/TShark Rows:  {len(pyshark_results)}")

    scapy_hosts = set(r[1] for r in scapy_results if r[1])
    scapy_snis = set(r[3] for r in scapy_results if r[3])
    py_hosts = set(r[1] for r in pyshark_results if r[1])
    py_snis = set(r[3] for r in pyshark_results if r[3])

    print(f"  Concordant Hosts:     {scapy_hosts & py_hosts}")
    print(f"  Concordant SNIs:      {scapy_snis & py_snis}")
    print("------------------------------------------------------------\n")

    return {
        "scapy_count": len(scapy_results),
        "pyshark_count": len(pyshark_results),
        "scapy_hosts": scapy_hosts,
        "scapy_snis": scapy_snis,
        "pyshark_hosts": py_hosts,
        "pyshark_snis": py_snis,
        "pyshark_error": pyshark_error,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract unencrypted HTTP requests and TLS Server Name Indication (SNI) records from a PCAP."
    )
    parser.add_argument("pcap", help="Path to PCAP capture file")
    parser.add_argument("-o", "--out", help="Output path for extracted CSV")
    parser.add_argument("--tshark-path", help="Explicit path to tshark.exe")
    parser.add_argument("--compare", action="store_true", help="Compare TShark and Scapy fallback extraction results")

    args = parser.parse_args()

    if args.compare:
        compare_engines(args.pcap, custom_tshark=args.tshark_path)
    else:
        extract_http_tls(args.pcap, out_csv=args.out, custom_tshark=args.tshark_path)


if __name__ == "__main__":
    main()
