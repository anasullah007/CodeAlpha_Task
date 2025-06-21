"""
 Network Packet Sniffer using Python & Scapy
 Internship Project - Code Alpha

 Description:
This script is a custom-built Network packet sniffer created as part of my 
internship with Code Alpha. It captures and analyzes real-time packets 
from a selected network interface (e.g., Wi-Fi or Ethernet).

It helps understand:
 How data flows through the network
 Common network protocols (TCP, UDP, ICMP)
 Structure of packets and headers
 Basics of packet inspection and filtering

 Key Features:
Interface selection (e.g., "Wi-Fi")
Protocol filter support (e.g., "icmp", "tcp port 80")
Packet count limiter (capture specific number of packets)
One-line packet summaries
Verbose mode to view full packet structure + raw payloads

How to Run:
Open Command Prompt (as Administrator) on Windows  
   Or Terminal with sudo on Linux/macOS
Run the script using:
   python Network_sniffer.py -i "Wi-Fi" -f "icmp" -c 10 -v

 Options:
`-i` → Interface name (e.g., "Wi-Fi")
 `-f` → Filter (optional, e.g., "tcp", "udp port 53", "icmp")
 `-c` → Number of packets to capture (default = infinite)
 `-v` → Verbose mode (shows full header and payload details)

 How to Stop:
- Press **Ctrl + C** anytime to stop packet capturing safely.

Learning Outcome:
- Understood how packet sniffers work internally
- Gained hands-on experience with real-world traffic
- Practiced Scapy and Python networking libraries
- Reinforced protocol structure (IP, TCP, UDP, ICMP)

Requirements:
 Python 3.x
 scapy (`pip install scapy`)

Created By: [Anasullah sharief]  
 Internship: Code Alpha – Network Sniffer 
Date: [21/06/25]
"""


import argparse
import datetime as dt
import os
import sys
from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, ICMP, Raw

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def timestamp(ts):
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def proto_name(pkt):
    if IP in pkt:
        return PROTOCOLS.get(pkt[IP].proto, str(pkt[IP].proto))
    if IPv6 in pkt:
        return PROTOCOLS.get(pkt[IPv6].nh, str(pkt[IPv6].nh))
    return "N/A"

def endpoints(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return "Unknown", "Unknown"

    if TCP in pkt:
        src += f":{pkt[TCP].sport}"
        dst += f":{pkt[TCP].dport}"
    elif UDP in pkt:
        src += f":{pkt[UDP].sport}"
        dst += f":{pkt[UDP].dport}"

    return src, dst

def summary_line(pkt):
    ts = timestamp(pkt.time)
    proto = proto_name(pkt)
    src, dst = endpoints(pkt)
    length = len(pkt)
    return f"{ts}  {proto:<5}  {src:<25} → {dst:<25}  {length:>5} B"

def handle(pkt):
    print(summary_line(pkt))
    if ARGS.verbose:
        pkt.show()
        if Raw in pkt and pkt[Raw].load:
            print("── Raw Payload ──")
            try:
                print(pkt[Raw].load.decode(errors="replace"))
            except:
                print(pkt[Raw].load)
            print("────────────────")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Packet Sniffer using Scapy")
    parser.add_argument("-i", "--iface", default=conf.iface, help="Interface to sniff on")
    parser.add_argument("-f", "--filter", default="", help='BPF filter like "tcp", "icmp", "port 53"')
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full packet details")
    ARGS = parser.parse_args()

    print(f"Sniffing on interface: {ARGS.iface}")
    print(f"Filter: {ARGS.filter or 'None'} | Count: {ARGS.count or '∞'} | Verbose: {ARGS.verbose}")
    print("-" * 80)

    try:
        sniff(iface=ARGS.iface, filter=ARGS.filter, prn=handle, store=False, count=ARGS.count)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Error: {e}")