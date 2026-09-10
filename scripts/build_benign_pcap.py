"""Builds a minimal, synthetic pcap containing a normal HTTP request to a
benign domain (not the case's C2 domain). Used only as a negative-test
fixture for detections/zeek/detect-c2-domain.zeek — contains no real or
case-derived data, purely synthetic traffic for test purposes.
"""
from scapy.all import IP, TCP, Raw, wrpcap

src_ip, dst_ip = "10.0.0.50", "93.184.216.34"  # example.com's documented IP block
src_port, dst_port = 51000, 80

http_request = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: benign-example.invalid\r\n"
    b"User-Agent: TestClient/1.0\r\n"
    b"Connection: close\r\n\r\n"
)

seq_client, seq_server = 1000, 5000

packets = [
    IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_client),
    IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq_server, ack=seq_client + 1),
    IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_client + 1, ack=seq_server + 1),
    IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq_client + 1, ack=seq_server + 1) / Raw(load=http_request),
    IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="A", seq=seq_server + 1, ack=seq_client + 1 + len(http_request)),
    IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=seq_server + 1, ack=seq_client + 1 + len(http_request)),
    IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_client + 1 + len(http_request), ack=seq_server + 2),
]

wrpcap("detections/tests/fixtures/benign-traffic.pcap", packets)
print("wrote detections/tests/fixtures/benign-traffic.pcap with", len(packets), "packets")
