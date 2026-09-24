from app.protocol.detector import analyze_session
from tests.fixtures import TLS_CLIENT_HELLO_BYTES, build_session


def test_pop3_normal_stls():
    session = build_session("p1", dst_port=110, script=[
        ("s2c", b"+OK POP3 server ready"),
        ("c2s", b"CAPA"),
        ("s2c", b"+OK"),
        ("s2c", b"STLS"),
        ("s2c", b"."),
        ("c2s", b"STLS"),
        ("s2c", b"+OK Begin TLS negotiation"),
        ("c2s", TLS_CLIENT_HELLO_BYTES),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "POP3"
    enc = analysis.encryption
    assert enc["mode"] == "STARTTLS"
    assert enc["accepted"] is True


def test_pop3_fragmented_command():
    session = build_session("p2", dst_port=110, script=[])
    session.add_s2c(b"+OK POP3 server ready\r\n", 1.0)
    session.add_c2s(b"US", 1.1)
    session.add_c2s(b"ER alice\r\n", 1.2)
    analysis = analyze_session(session)
    assert any(e.command == "USER" for e in analysis.events)


def test_pop3_plaintext_auth_no_stls():
    session = build_session("p3", dst_port=110, script=[
        ("s2c", b"+OK POP3 server ready"),
        ("c2s", b"USER alice"),
        ("s2c", b"+OK"),
        ("c2s", b"PASS secret"),
        ("s2c", b"+OK maildrop ready"),
    ])
    analysis = analyze_session(session)
    enc = analysis.encryption
    assert enc["tls_detected"] is False
    for event in analysis.events:
        if event.command == "PASS":
            assert "REDACTED" in event.evidence
