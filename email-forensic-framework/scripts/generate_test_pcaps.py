from scapy.all import Ether, IP, TCP, wrpcap
import os
from pathlib import Path

PCAPS_DIR = Path("pcaps")
PCAPS_DIR.mkdir(exist_ok=True)

def build_pkt(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    eth = Ether()
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    
    if payload:
        return eth/ip/tcp/payload
    return eth/ip/tcp

def generate_normal():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12345, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 80, 1001, 2001, "PA", b"GET / HTTP/1.1\r\n\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12345, 2001, 1019, "PA", b"HTTP/1.1 200 OK\r\n\r\n"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 80, 1019, 2020, "FA"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12345, 2020, 1020, "FA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 80, 1020, 2021, "A"),
    ]
    wrpcap(str(PCAPS_DIR / "normal.pcap"), pkts)
    
def generate_out_of_order():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12346, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 80, 1021, 2001, "PA", b"world"), # seq 1021
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 80, 1001, 2001, "PA", b"hello_"), # seq 1001
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 80, 1007, 2001, "PA", b"beautiful_"), # seq 1007
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12346, 2001, 1026, "FA"),
    ]
    wrpcap(str(PCAPS_DIR / "out_of_order.pcap"), pkts)

def generate_retransmission():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12347, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 80, 1001, 2001, "PA", b"payload1"), 
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 80, 1001, 2001, "PA", b"payload1"), # exact retransmission
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12347, 2001, 1009, "FA"),
    ]
    wrpcap(str(PCAPS_DIR / "retransmission.pcap"), pkts)

def generate_overlap():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12348, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 80, 1001, 2001, "PA", b"AAAA"), # seq 1001-1005
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 80, 1003, 2001, "PA", b"BBBB"), # seq 1003-1007 (Overlap of 2 bytes)
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12348, 2001, 1007, "FA"),
    ]
    wrpcap(str(PCAPS_DIR / "overlap.pcap"), pkts)

def generate_missing():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12349, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12349, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12349, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12349, 80, 1001, 2001, "PA", b"data1"), # 1001-1006
        build_pkt("10.0.0.1", "10.0.0.2", 12349, 80, 1016, 2001, "PA", b"data3"), # 1016-1021 (Gap 1006-1016)
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12349, 2001, 1021, "FA"),
    ]
    wrpcap(str(PCAPS_DIR / "missing.pcap"), pkts)

def generate_rst():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12350, 80, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12350, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12350, 80, 1001, 2001, "A"),
        build_pkt("10.0.0.1", "10.0.0.2", 12350, 80, 1001, 2001, "PA", b"data"),
        build_pkt("10.0.0.2", "10.0.0.1", 80, 12350, 2001, 1005, "R"),
    ]
    wrpcap(str(PCAPS_DIR / "rst.pcap"), pkts)

if __name__ == "__main__":
    generate_normal()
    generate_out_of_order()
    generate_retransmission()
    generate_overlap()
    generate_missing()
    generate_rst()
    print("Generated 6 synthetic PCAPs in 'pcaps/' directory.")
