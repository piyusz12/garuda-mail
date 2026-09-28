from app.protocol.detector import analyze_session
from tests.fixtures import TLS_CLIENT_HELLO_BYTES, build_session


def test_smtp_normal_starttls_success():
    session = build_session("t1", dst_port=587, script=[
        ("s2c", b"220 mail.example.com ESMTP"),
        ("c2s", b"EHLO workstation.local"),
        ("s2c", b"250-mail.example.com"),
        ("s2c", b"250-STARTTLS"),
        ("c2s", b"STARTTLS"),
        ("s2c", b"220 2.0.0 Ready to start TLS"),
        ("c2s", TLS_CLIENT_HELLO_BYTES),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "SMTP"
    enc = analysis.encryption
    assert enc["mode"] == "STARTTLS"
    assert enc["offered"] and enc["requested"] and enc["accepted"]
    assert enc["tls_detected"] is True
    assert enc["boundary"]["direction"] == "client_to_server"


def test_smtp_non_standard_port_still_detected():
    session = build_session("t2", dst_port=4444, script=[
        ("s2c", b"220 mail.example.com ESMTP"),
        ("c2s", b"EHLO workstation"),
        ("s2c", b"250 mail.example.com"),
        ("c2s", b"MAIL FROM:<a@example.com>"),
        ("c2s", b"RCPT TO:<b@example.com>"),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "SMTP"
    assert analysis.confidence >= 0.9


def test_smtp_fragmented_starttls_command_detected():
    session = build_session("t3", dst_port=587, script=[
        ("s2c", b"220 mail.example.com ESMTP"),
        ("c2s", b"EHLO workstation"),
        ("s2c", b"250-STARTTLS"),
        ("c2s", b"STARTTLS"),  # will be split by fragment_first
    ], fragment_first=False)
    # simulate fragmentation manually across two add_c2s calls for STARTTLS
    session.client_to_server = b""
    session.c2s_chunks = []
    session.add_c2s(b"EHLO workstation\r\n", 1.0)
    session.add_c2s(b"STAR", 1.1)
    session.add_c2s(b"TTLS\r\n", 1.2)
    analysis = analyze_session(session)
    assert any(e.command == "STARTTLS" for e in analysis.events if e.event_type.value == "STARTTLS_REQUEST")


def test_smtp_starttls_rejected():
    session = build_session("t4", dst_port=25, script=[
        ("s2c", b"220 mail.example.com"),
        ("c2s", b"EHLO workstation"),
        ("s2c", b"250-STARTTLS"),
        ("c2s", b"STARTTLS"),
        ("s2c", b"454 TLS not available"),
        ("c2s", b"MAIL FROM:<user@example.com>"),
    ])
    analysis = analyze_session(session)
    enc = analysis.encryption
    assert enc["rejected"] is True
    assert enc["tls_detected"] is False
    indicator_types = {i["type"] for i in enc["security_indicators"]}
    assert "STARTTLS_FAILURE" in indicator_types
    assert "PLAINTEXT_CONTINUATION" in indicator_types


def test_smtp_starttls_offered_but_not_used_flags_plaintext_auth():
    session = build_session("t5", dst_port=25, script=[
        ("s2c", b"220 mail.example.com"),
        ("c2s", b"EHLO workstation"),
        ("s2c", b"250-STARTTLS"),
        ("c2s", b"AUTH PLAIN AGFsaWNlAHNlY3JldA=="),
        ("s2c", b"235 Authentication successful"),
    ])
    analysis = analyze_session(session)
    enc = analysis.encryption
    indicator_types = {i["type"] for i in enc["security_indicators"]}
    assert "STARTTLS_NOT_USED" in indicator_types
    assert "PLAINTEXT_AUTHENTICATION" in indicator_types
    # credentials must never be retained verbatim
    for event in analysis.events:
        if event.command == "AUTH":
            assert "REDACTED" in event.evidence
            assert "AGFsaWNl" not in event.evidence


def test_smtp_port_payload_conflict_recorded():
    session = build_session("t6", dst_port=143, script=[  # 143 is IMAP's port
        ("s2c", b"220 smtp.example.com ESMTP"),
        ("c2s", b"EHLO workstation"),
        ("s2c", b"250 smtp.example.com"),
        ("c2s", b"MAIL FROM:<a@example.com>"),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "SMTP"
    assert analysis.port_protocol_conflict is True
    assert analysis.port_hint == "IMAP"


def test_smtp_truncated_session_reports_partial():
    session = build_session("t7", dst_port=587, script=[
        ("s2c", b"220 mail.example.com ESMTP"),
        ("c2s", b"EHLO workstation"),
    ], truncated=True)
    analysis = analyze_session(session)
    assert analysis.parse_status == "PARTIAL"


def test_unknown_protocol_when_no_signatures_match():
    session = build_session("t8", dst_port=9999, script=[
        ("s2c", b"random binary blob not a protocol"),
        ("c2s", b"more random junk here too"),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "UNKNOWN"
