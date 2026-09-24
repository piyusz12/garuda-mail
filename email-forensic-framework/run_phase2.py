#!/usr/bin/env python3
"""
run_phase2.py

Standalone demo of the Phase 2 pipeline (protocol identification +
encryption transition analysis) using synthetic sessions that mirror
the worked examples in the design spec: a clean SMTP STARTTLS upgrade,
an insecure plaintext-auth SMTP session, a failed STARTTLS negotiation,
an IMAP STARTTLS session, and a POP3 STLS session.

In production, replace `build_demo_sessions()` with sessions coming
out of Phase 1 (app/reassembly), and run `analyze_session()` on each.

Usage:
    python run_phase2.py
"""

from __future__ import annotations

from app.protocol.detector import analyze_session
from app.storage.writer import write_analysis
from tests.fixtures import TLS_CLIENT_HELLO_BYTES, build_session


def build_demo_sessions():
    sessions = []

    # 1. Clean SMTP STARTTLS upgrade (design doc section 30).
    sessions.append(build_session(
        "FLOW-00042", dst_port=587,
        script=[
            ("s2c", b"220 mail.example.com ESMTP"),
            ("c2s", b"EHLO workstation.local"),
            ("s2c", b"250-mail.example.com"),
            ("s2c", b"250-STARTTLS"),
            ("s2c", b"250-AUTH PLAIN LOGIN"),
            ("c2s", b"STARTTLS"),
            ("s2c", b"220 2.0.0 Ready to start TLS"),
            ("c2s", TLS_CLIENT_HELLO_BYTES),
        ],
    ))

    # 2. Insecure SMTP: STARTTLS offered but never used, auth in plaintext
    #    (design doc section 31).
    sessions.append(build_session(
        "FLOW-00043", dst_port=25,
        script=[
            ("s2c", b"220 mail.example.com"),
            ("c2s", b"EHLO workstation"),
            ("s2c", b"250-STARTTLS"),
            ("c2s", b"AUTH PLAIN AGFsaWNlAHNlY3JldA=="),
            ("s2c", b"235 Authentication successful"),
        ],
    ))

    # 3. Failed STARTTLS transition, plaintext continues (section 32).
    sessions.append(build_session(
        "FLOW-00044", dst_port=25,
        script=[
            ("s2c", b"220 mail.example.com"),
            ("c2s", b"EHLO workstation"),
            ("s2c", b"250-STARTTLS"),
            ("c2s", b"STARTTLS"),
            ("s2c", b"454 TLS not available"),
            ("c2s", b"MAIL FROM:<user@example.com>"),
        ],
    ))

    # 4. IMAP STARTTLS upgrade with arbitrary tags (section 33).
    sessions.append(build_session(
        "FLOW-00045", dst_port=143,
        script=[
            ("s2c", b"* OK IMAP4rev1 Ready"),
            ("c2s", b"X1 CAPABILITY"),
            ("s2c", b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"),
            ("s2c", b"X1 OK CAPABILITY completed"),
            ("c2s", b"X2 STARTTLS"),
            ("s2c", b"X2 OK Begin TLS negotiation now"),
            ("c2s", TLS_CLIENT_HELLO_BYTES),
        ],
    ))

    # 5. POP3 STLS upgrade (section 34), with a fragmented first command
    #    to exercise the reassembly-dependent fragmentation handling.
    sessions.append(build_session(
        "FLOW-00046", dst_port=110,
        script=[
            ("s2c", b"+OK POP3 server ready"),
            ("c2s", b"CAPA"),
            ("s2c", b"+OK"),
            ("s2c", b"STLS"),
            ("s2c", b"USER"),
            ("s2c", b"."),
            ("c2s", b"STLS"),
            ("s2c", b"+OK Begin TLS negotiation"),
            ("c2s", TLS_CLIENT_HELLO_BYTES),
        ],
        fragment_first=True,
    ))

    # 6. Non-standard port SMTP (port/payload agree, port hint is None).
    sessions.append(build_session(
        "FLOW-00047", dst_port=8080,
        script=[
            ("s2c", b"220 mail.example.com ESMTP"),
            ("c2s", b"EHLO workstation"),
            ("s2c", b"250 mail.example.com"),
            ("c2s", b"MAIL FROM:<a@example.com>"),
            ("c2s", b"RCPT TO:<b@example.com>"),
        ],
    ))

    # 7. Port/payload conflict: port says IMAP, payload says SMTP
    #    (section 28).
    sessions.append(build_session(
        "FLOW-00048", dst_port=143,
        script=[
            ("s2c", b"220 smtp.example.com ESMTP"),
            ("c2s", b"EHLO workstation"),
            ("s2c", b"250 smtp.example.com"),
            ("c2s", b"MAIL FROM:<a@example.com>"),
        ],
    ))

    return sessions


def print_summary(analysis) -> None:
    d = analysis.to_dict()
    print(f"\n=== {d['session_id']} ===")
    print(f"  Protocol       {d['protocol']['name']} "
          f"(confidence {d['protocol']['confidence']:.2f}, {d['protocol']['confidence_bucket']})")
    if d["port_protocol_conflict"]:
        print(f"  ! Port/payload conflict -- port suggests {d['port_hint']}")
    enc = d["encryption"]
    print(f"  Encryption     mode={enc['mode']}  tls_detected={enc['tls_detected']}")
    print(f"  STARTTLS       offered={enc['offered']} requested={enc['requested']} "
          f"accepted={enc['accepted']} rejected={enc['rejected']}")
    if enc["boundary"]:
        b = enc["boundary"]
        print(f"  TLS boundary   direction={b['direction']} offset={b['offset']}")
    if enc["security_indicators"]:
        print("  Security indicators:")
        for ind in enc["security_indicators"]:
            print(f"    - {ind['type']} ({ind['severity_hint']})")
    print("  Event timeline:")
    for ev in d["events"]:
        print(f"    [{ev['direction']:>15}] offset={ev['stream_offset']:<5} {ev['event_type']:<20} {ev['evidence']}")


def main() -> None:
    sessions = build_demo_sessions()
    for session in sessions:
        analysis = analyze_session(session)
        print_summary(analysis)
        path = write_analysis(analysis)
        print(f"  -> wrote {path}")


if __name__ == "__main__":
    main()
