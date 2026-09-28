from scapy.all import Ether, IP, TCP, wrpcap
import os
from pathlib import Path
import binascii

PCAPS_DIR = Path("pcaps")
PCAPS_DIR.mkdir(exist_ok=True)

def build_pkt(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    eth = Ether()
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    
    if payload:
        return eth/ip/tcp/payload
    return eth/ip/tcp

TLS_CLIENT_HELLO = bytes.fromhex("16030100c6010000c20303" + "00" * 32) # Mock ClientHello

def generate_smtp_starttls():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 25, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12345, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 25, 1001, 2001, "A"),
        
        # SMTP Protocol
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12345, 2001, 1001, "PA", b"220 mail.example.com ESMTP\r\n"),
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 25, 1001, 2029, "PA", b"EHLO workstation\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12345, 2029, 1019, "PA", b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"),
        
        # Encryption Upgrade
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 25, 1019, 2085, "PA", b"STARTTLS\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12345, 2085, 1029, "PA", b"220 2.0.0 Ready to start TLS\r\n"),
        
        # TLS Boundary
        build_pkt("10.0.0.1", "10.0.0.2", 12345, 25, 1029, 2115, "PA", TLS_CLIENT_HELLO),
    ]
    wrpcap(str(PCAPS_DIR / "smtp_starttls.pcap"), pkts)
    
def generate_smtp_insecure():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 25, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12346, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 25, 1001, 2001, "A"),
        
        # SMTP Protocol
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12346, 2001, 1001, "PA", b"220 mail.example.com ESMTP\r\n"),
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 25, 1001, 2029, "PA", b"EHLO workstation\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12346, 2029, 1019, "PA", b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"),
        
        # Plaintext Auth
        build_pkt("10.0.0.1", "10.0.0.2", 12346, 25, 1019, 2085, "PA", b"AUTH PLAIN dXNlcjpwYXNzd29yZA==\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 25, 12346, 2085, 1052, "PA", b"235 Authentication successful\r\n"),
    ]
    wrpcap(str(PCAPS_DIR / "smtp_insecure.pcap"), pkts)

def generate_imap_starttls():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 143, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 143, 12347, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 143, 1001, 2001, "A"),
        
        # IMAP Protocol
        build_pkt("10.0.0.2", "10.0.0.1", 143, 12347, 2001, 1001, "PA", b"* OK IMAP4rev1 Ready\r\n"),
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 143, 1001, 2023, "PA", b"A001 CAPABILITY\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 143, 12347, 2023, 1018, "PA", b"* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK\r\n"),
        
        # Upgrade
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 143, 1018, 2063, "PA", b"A002 STARTTLS\r\n"),
        build_pkt("10.0.0.2", "10.0.0.1", 143, 12347, 2063, 1033, "PA", b"A002 OK Begin TLS negotiation now\r\n"),
        
        # TLS Boundary
        build_pkt("10.0.0.1", "10.0.0.2", 12347, 143, 1033, 2098, "PA", TLS_CLIENT_HELLO),
    ]
    wrpcap(str(PCAPS_DIR / "imap_starttls.pcap"), pkts)
    
def generate_implicit_tls():
    pkts = [
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 465, 1000, 0, "S"),
        build_pkt("10.0.0.2", "10.0.0.1", 465, 12348, 2000, 1001, "SA"),
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 465, 1001, 2001, "A"),
        
        # Immediate TLS Handshake
        build_pkt("10.0.0.1", "10.0.0.2", 12348, 465, 1001, 2001, "PA", TLS_CLIENT_HELLO),
    ]
    wrpcap(str(PCAPS_DIR / "implicit_tls.pcap"), pkts)

if __name__ == "__main__":
    generate_smtp_starttls()
    generate_smtp_insecure()
    generate_imap_starttls()
    generate_implicit_tls()
    print("Generated Phase 2 synthetic PCAPs in 'pcaps/' directory.")
