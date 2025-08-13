#!/usr/bin/env python3
"""
Simple Packet Sniffer (educational use only).
Requires: scapy (pip install scapy)
Run as root/Administrator. Use only on networks you own or have permission to monitor.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime
import argparse
import sys

def safe_decode(payload_bytes):
    """Try to decode payload as UTF-8, fallback to hex if not printable."""
    if not payload_bytes:
        return ""
    try:
        text = payload_bytes.decode('utf-8')
        # if contains many non-printable, return hex
        if any(ord(c) < 32 and c not in '\r\n\t' for c in text):
            raise ValueError
        return text
    except Exception:
        return payload_bytes.hex()

def handle_packet(pkt):
    """Called for each sniffed packet."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{ts}] "

    # IP layer
    ip_layer = pkt.getlayer(IP)
    if ip_layer:
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        line += f"{src} -> {dst} (proto={proto})"
    else:
        # Non-IP packet (ARP, etc.)
        line += pkt.summary()
        print(line)
        return

    # Transport layer specifics
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        line += f" TCP {tcp.sport} -> {tcp.dport} flags={tcp.flags}"
    elif pkt.haslayer(UDP):
        udp = pkt.getlayer(UDP)
        line += f" UDP {udp.sport} -> {udp.dport}"
    elif pkt.haslayer(ICMP):
        icmp = pkt.getlayer(ICMP)
        line += f" ICMP type={icmp.type} code={icmp.code}"
    else:
        line += " (no TCP/UDP/ICMP)"

    print(line)

    # Payload (Raw)
    if pkt.haslayer(Raw):
        raw_bytes = pkt.getlayer(Raw).load
        decoded = safe_decode(raw_bytes)
        # keep payload short in console
        short = decoded if len(str(decoded)) <= 200 else str(decoded)[:200] + "..."
        print(f"    Payload: {short}")

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer (educational use only)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (optional).")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string (e.g., 'tcp port 80').")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite).")
    parser.add_argument("-t", "--timeout", type=int, default=0, help="Timeout in seconds (0 = none).")
    parser.add_argument("-w", "--write", help="Write captured packets to pcap file (e.g., capture.pcap).")
    args = parser.parse_args()

    try:
        print("[*] Starting packet capture. Press CTRL+C to stop.")
        sniff_kwargs = {
            "prn": handle_packet,
            "filter": args.filter if args.filter else None,
            "count": args.count if args.count > 0 else 0,
            "timeout": args.timeout if args.timeout > 0 else None,
            "iface": args.interface if args.interface else None,
            "store": True if args.write else False
        }

        # remove None values (Scapy sniff doesn't like explicit None for filter/interface)
        sniff_kwargs = {k: v for k, v in sniff_kwargs.items() if v is not None}

        packets = sniff(**sniff_kwargs)

        if args.write:
            wrpcap(args.write, packets)
            print(f"[*] Saved {len(packets)} packets to {args.write}")

    except PermissionError:
        print("[!] Permission denied. Try running as root / Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
        if args.write and 'packets' in locals():
            wrpcap(args.write, packets)
            print(f"[*] Saved {len(packets)} packets to {args.write}")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()