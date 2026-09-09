"""Reassembles raw TCP payload bytes for a given flow directly from the pcap,
independent of Zeek's file-extraction analyzer. Use to cross-check Zeek's
extracted file against an independently-derived byte stream.

Usage: python3 scripts/extract_raw_tcp_payload.py <src_ip> <src_port> <dst_ip> <dst_port> <output_path>
"""
import sys
from scapy.all import rdpcap, TCP, IP

def main():
    if len(sys.argv) != 6:
        print(__doc__)
        sys.exit(1)

    src_ip, src_port, dst_ip, dst_port, output_path = sys.argv[1:]
    src_port, dst_port = int(src_port), int(dst_port)

    packets = rdpcap("original/evidence/network/incident.pcap")
    payload = b""
    packet_count = 0

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        if ip.src == src_ip and tcp.sport == src_port and ip.dst == dst_ip and tcp.dport == dst_port:
            if tcp.payload:
                payload += bytes(tcp.payload)
                packet_count += 1

    with open(output_path, "wb") as f:
        f.write(payload)

    print(f"matched packets: {packet_count}")
    print(f"total bytes written: {len(payload)}")
    print(f"output: {output_path}")

if __name__ == "__main__":
    main()
