"""
Quick demo of Phase 6 output — run with:
    python scripts/demo_phase6.py
"""
import sys
import json

sys.path.insert(0, ".")

from app.sessions.manager import SessionManager


def main():
    manager = SessionManager()

    # ── Scenario 1: SMTP with successful STARTTLS ──
    server_stream = (
        b"220 mail.example.com ESMTP Postfix\r\n"
        b"250-mail.example.com\r\n"
        b"250-PIPELINING\r\n"
        b"250-SIZE 10240000\r\n"
        b"250-STARTTLS\r\n"
        b"250-AUTH LOGIN PLAIN\r\n"
        b"250 8BITMIME\r\n"
        b"220 2.0.0 Ready to start TLS\r\n"
    )
    tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40
    client_stream = (
        b"EHLO client.example.com\r\n"
        b"STARTTLS\r\n"
    ) + tls_hello

    session = manager.process_flow(
        flow_id="FLOW-00001",
        protocol="SMTP",
        client_ip="192.168.1.20",
        client_port=49152,
        server_ip="10.0.0.10",
        server_port=587,
        client_stream=client_stream,
        server_stream=server_stream,
        start_time=1758754301.0,
    )

    print(session.summary())
    print()

    # ── Scenario 2: SMTP with AUTH before TLS (security risk) ──
    server2 = (
        b"220 insecure.mail.com ESMTP\r\n"
        b"250-insecure.mail.com\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH PLAIN LOGIN\r\n"
        b"235 2.7.0 Authentication successful\r\n"
        b"250 2.1.0 Ok\r\n"
        b"250 2.1.5 Ok\r\n"
        b"354 End data with <CR><LF>.<CR><LF>\r\n"
        b"250 2.0.0 Ok: queued\r\n"
    )
    client2 = (
        b"EHLO client.example.com\r\n"
        b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
        b"MAIL FROM:<sender@example.com>\r\n"
        b"RCPT TO:<victim@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: Sensitive\r\n"
        b"\r\n"
        b"Secret content\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )

    session2 = manager.process_flow(
        flow_id="FLOW-00002",
        protocol="SMTP",
        client_ip="10.10.10.50",
        client_port=49200,
        server_ip="172.16.0.100",
        server_port=25,
        client_stream=client2,
        server_stream=server2,
        start_time=1758754400.0,
    )

    print(session2.summary())
    print()

    # ── JSON export ──
    print("=" * 56)
    print("JSON Export (Session 1)")
    print("=" * 56)
    print(json.dumps(session.to_dict(), indent=2))


if __name__ == "__main__":
    main()
