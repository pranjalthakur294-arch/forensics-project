import asyncio
import pyshark

# Fix for Python 3.12+ (including 3.14)
asyncio.set_event_loop(asyncio.new_event_loop())

cap = pyshark.LiveCapture(interface="Intel(R) Wi-Fi 6E AX211 _")
cap.sniff(packet_count=20)

for pkt in cap:
    print(pkt)
