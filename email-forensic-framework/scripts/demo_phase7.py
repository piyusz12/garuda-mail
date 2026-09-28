"""
Quick demo of Phase 7 output — run with:
    python scripts/demo_phase7.py
"""
import sys
import json

sys.path.insert(0, ".")

from app.sessions.manager import SessionManager
from app.transition.analyzer import TLSUpgradeAnalyzer


TLS_HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40


def main():
    mgr = SessionManager()
    analyzer = TLSUpgradeAnalyzer()

    # ── Scenario 1: Successful STARTTLS ──
    s1 = mgr.process_flow(
        flow_id="FLOW-001", protocol="SMTP",
        client_ip="192.168.1.20", client_port=49152,
        server_ip="10.0.0.10", server_port=587,
        client_stream=(
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
        ) + TLS_HELLO,
        server_stream=(
            b"220 mail.example.com ESMTP Postfix\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250-AUTH LOGIN PLAIN\r\n"
            b"250 8BITMIME\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        ),
        start_time=1758754301.0,
    )
    r1 = analyzer.analyze(s1)
    print(r1.summary())
    print()

    # ── Scenario 2: STARTTLS Rejected + Auth Before TLS ──
    s2 = mgr.process_flow(
        flow_id="FLOW-002", protocol="SMTP",
        client_ip="10.10.10.50", client_port=49200,
        server_ip="172.16.0.100", server_port=25,
        client_stream=(
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
            b"AUTH LOGIN dXNlcg==\r\n"
        ),
        server_stream=(
            b"220 insecure.mail.com ESMTP\r\n"
            b"250-insecure.mail.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"454 TLS not available due to temporary reason\r\n"
            b"235 2.7.0 Authentication successful\r\n"
        ),
        start_time=1758754400.0,
    )
    r2 = analyzer.analyze(s2)
    print(r2.summary())
    print()

    # ── Scenario 3: Plaintext Session (No TLS at all) ──
    s3 = mgr.process_flow(
        flow_id="FLOW-003", protocol="SMTP",
        client_ip="10.10.10.60", client_port=49300,
        server_ip="172.16.0.200", server_port=25,
        client_stream=(
            b"EHLO client.example.com\r\n"
            b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
            b"MAIL FROM:<sender@example.com>\r\n"
            b"RCPT TO:<victim@example.com>\r\n"
            b"DATA\r\n"
            b".\r\n"
            b"QUIT\r\n"
        ),
        server_stream=(
            b"220 old.mail.com ESMTP\r\n"
            b"250-old.mail.com\r\n"
            b"250 AUTH PLAIN\r\n"
            b"235 2.7.0 Authentication successful\r\n"
            b"250 2.1.0 Ok\r\n"
            b"250 2.1.5 Ok\r\n"
            b"354 End data\r\n"
            b"250 2.0.0 Ok: queued\r\n"
        ),
        start_time=1758754500.0,
    )
    r3 = analyzer.analyze(s3)
    print(r3.summary())
    print()

    # ── JSON export ──
    print("=" * 56)
    print("JSON Export (Scenario 1)")
    print("=" * 56)
    print(json.dumps(r1.to_dict(), indent=2))


if __name__ == "__main__":
    main()
