"""
wifi_sniffer.py - Portable Network Interface Sniffer & Packet Acquisition Tool
Part of the Digital Forensics Portfolio Toolset.

Functionality:
- Captures live network traffic from specified or auto-discovered network adapters
- Portably lists available network adapters across Windows and Linux
- Supports packet count limits and timeout thresholds
- Saves captured packets into standard PCAP files for forensic analysis
- Provides clear diagnostics if Npcap/WinPcap drivers or elevated permissions are missing

IMPORTANT LEGAL & ETHICAL NOTICE:
Unauthorized interception of electronic communications is illegal under applicable
wiretap and computer crime legislation (e.g., 18 U.S.C. § 2511).
Only capture traffic on networks and interfaces you own or have explicit written authorization to monitor.
"""

import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional

try:
    from scapy.all import sniff, wrpcap, conf
except ImportError:
    sys.exit("Error: Scapy is required. Install it using: pip install scapy")


def list_network_interfaces() -> List[dict]:
    """Enumerate and display available network adapters with friendly names."""
    interfaces = []
    print("\n--- Available Network Interfaces ---")
    if os.name == "nt":
        try:
            from scapy.arch.windows import get_windows_if_list
            raw_ifs = get_windows_if_list()
            for idx, item in enumerate(raw_ifs, start=1):
                name = item.get("name", "Unknown")
                desc = item.get("description", "")
                guid = item.get("guid", "")
                ips = item.get("ips", [])
                interfaces.append({"id": idx, "name": name, "description": desc, "guid": guid})
                print(f"  [{idx:>2}] {name:<25} | {desc}")
                if ips:
                    print(f"       IPs: {', '.join(ips)}")
        except Exception as e:
            print(f"[!] Could not query Windows interface list via Npcap: {e}")
    else:
        # POSIX
        for idx, iface_name in enumerate(conf.ifaces.keys(), start=1):
            interfaces.append({"id": idx, "name": iface_name, "description": iface_name})
            print(f"  [{idx:>2}] {iface_name}")

    print("------------------------------------\n")
    return interfaces


def find_default_wifi_or_active_interface() -> Optional[str]:
    """Attempt auto-detecting an active Wi-Fi or primary network adapter."""
    if os.name == "nt":
        try:
            from scapy.arch.windows import get_windows_if_list
            ifs = get_windows_if_list()
            # 1. Prefer interface containing 'wi-fi' or 'wireless'
            for item in ifs:
                name = (item.get("name") or "").lower()
                desc = (item.get("description") or "").lower()
                if "wi-fi" in name or "wireless" in desc or "802.11" in desc:
                    return item.get("name")
            # 2. Fallback to active interface with an IP
            for item in ifs:
                if item.get("ips"):
                    return item.get("name")
        except Exception:
            pass
    return None


def capture_traffic(
    interface: str = None,
    packet_count: int = 20,
    timeout: int = 30,
    output_pcap: str = None,
    filter_bpf: str = None,
) -> List:
    """Capture live network packets safely with validation and proper error handling."""
    if not interface:
        interface = find_default_wifi_or_active_interface()
        if not interface:
            print("[!] No active Wi-Fi adapter auto-detected. Use --list to view interfaces and specify one with -i.")
            sys.exit(1)
        print(f"[*] Auto-selected network interface: '{interface}'")
    else:
        print(f"[*] Using specified network interface: '{interface}'")

    print(f"[*] Starting packet acquisition (Count limit: {packet_count}, Timeout: {timeout}s)...")
    print("[*] Press Ctrl+C at any time to halt acquisition.")

    captured_packets = []
    try:
        kwargs = {
            "iface": interface,
            "count": packet_count,
            "timeout": timeout,
        }
        if filter_bpf:
            kwargs["filter"] = filter_bpf

        captured_packets = sniff(**kwargs)

    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user (Ctrl+C). Finalizing capture...")
    except PermissionError:
        print(
            "\n[!] PERMISSION ERROR: Packet capture requires elevated administrative privileges.\n"
            "    On Windows: Run PowerShell / Terminal as Administrator.\n"
            "    On Linux/macOS: Run with 'sudo'.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        err_msg = str(e)
        if "Npcap" in err_msg or "pcap" in err_msg.lower():
            print(
                f"\n[!] DRIVER ERROR: {err_msg}\n"
                "    Ensure Npcap is installed on Windows with 'WinPcap API-compatible mode' checked.\n"
                "    Download from: https://npcap.com/",
                file=sys.stderr,
            )
        else:
            print(f"\n[!] Packet capture failed: {err_msg}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Acquisition complete: Captured {len(captured_packets)} packets.")

    # Print summary of first few captured packets
    for i, p in enumerate(captured_packets[:5], start=1):
        print(f"    Packet #{i}: {p.summary()}")
    if len(captured_packets) > 5:
        print(f"    ... and {len(captured_packets) - 5} more packets.")

    # Save to PCAP file if requested
    if output_pcap and captured_packets:
        try:
            wrpcap(output_pcap, captured_packets)
            print(f"[+] Saved capture to PCAP artifact: {output_pcap}")
        except Exception as e:
            print(f"[!] Failed to write PCAP file '{output_pcap}': {e}", file=sys.stderr)

    return captured_packets


def main():
    parser = argparse.ArgumentParser(
        description="Portable Network Packet Capture & Wi-Fi Sniffer Tool (Authorized Monitoring Only)"
    )
    parser.add_argument("-l", "--list", action="store_true", help="List all available network interfaces and exit")
    parser.add_argument("-i", "--interface", help="Interface name or description to capture on")
    parser.add_argument("-c", "--count", type=int, default=20, help="Maximum number of packets to capture (default: 20)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Capture timeout in seconds (default: 30)")
    parser.add_argument("-o", "--out", help="Output path to save captured packets (.pcap)")
    parser.add_argument("-f", "--filter", help="Optional Berkeley Packet Filter (BPF) expression (e.g. 'tcp port 80')")

    args = parser.parse_args()

    if args.list:
        list_network_interfaces()
        sys.exit(0)

    # Print legal notice banner
    print("=" * 68)
    print("  AUTHORIZED MONITORING ONLY — DIGITAL FORENSICS PORTFOLIO TOOL")
    print("  Ensure you have explicit authorization before sniffing network traffic.")
    print("=" * 68)

    capture_traffic(
        interface=args.interface,
        packet_count=args.count,
        timeout=args.timeout,
        output_pcap=args.out,
        filter_bpf=args.filter,
    )


if __name__ == "__main__":
    main()
