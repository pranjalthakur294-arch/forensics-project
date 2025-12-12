# pyshark_http_tls.py
"""
Extract HTTP host/uri and TLS SNI from a pcap using pyshark (tshark backend).
Fixes asyncio eventloop for Python 3.12+ by creating an event loop.
Usage:
    python pyshark_http_tls.py test_capture.pcap
Produces:
    http_tls_extracted.csv
"""

import asyncio
import pyshark
import sys
import csv

# Fix for Python 3.12+ where there is no implicit event loop
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

def extract(pcap, out_csv="http_tls_extracted.csv"):
    cap = pyshark.FileCapture(pcap, use_json=True)  # reading from file
    rows = []
    try:
        for pkt in cap:
            try:
                ts = pkt.sniff_time.isoformat(sep=' ')
            except Exception:
                ts = ""
            # HTTP
            http_host = None
            http_uri = None
            tls_sni = None
            if hasattr(pkt, 'http'):
                http = pkt.http
                http_host = getattr(http, 'host', None)
                http_uri = getattr(http, 'request_uri', None)
                # pyshark returns attributes possibly as bytes-like; convert to str
                if http_host is not None:
                    http_host = str(http_host)
                if http_uri is not None:
                    http_uri = str(http_uri)
            # TLS SNI (varies by tshark version)
            if hasattr(pkt, 'tls'):
                tls = pkt.tls
                # handshake_extensions_server_name is common
                sni = getattr(tls, 'handshake_extensions_server_name', None)
                if sni:
                    tls_sni = str(sni)
                else:
                    # alternative field names
                    sni2 = getattr(tls, 'server_name', None)
                    if sni2:
                        tls_sni = str(sni2)

            if http_host or http_uri or tls_sni:
                rows.append((ts, http_host or "", http_uri or "", tls_sni or ""))
    finally:
        try:
            cap.close()
        except Exception:
            pass

    # write CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","http_host","http_uri","tls_sni"])
        for r in rows:
            writer.writerow(r)
    print("Wrote", out_csv, "rows:", len(rows))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pyshark_http_tls.py <pcap>")
        sys.exit(1)
    extract(sys.argv[1])
