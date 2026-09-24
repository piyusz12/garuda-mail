from app.protocol.detector import analyze_session
from tests.fixtures import TLS_CLIENT_HELLO_BYTES, build_session


def test_imap_normal_starttls_with_arbitrary_tags():
    session = build_session("i1", dst_port=143, script=[
        ("s2c", b"* OK IMAP4rev1 Ready"),
        ("c2s", b"X1 CAPABILITY"),
        ("s2c", b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"),
        ("s2c", b"X1 OK CAPABILITY completed"),
        ("c2s", b"X2 STARTTLS"),
        ("s2c", b"X2 OK Begin TLS negotiation now"),
        ("c2s", TLS_CLIENT_HELLO_BYTES),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "IMAP"
    enc = analysis.encryption
    assert enc["mode"] == "STARTTLS"
    assert enc["accepted"] is True
    assert enc["tls_detected"] is True


def test_imap_different_tag_scheme_still_detected():
    session = build_session("i2", dst_port=143, script=[
        ("s2c", b"* OK IMAP4rev1 Ready"),
        ("c2s", b"A001 LOGIN alice secret"),
        ("s2c", b"A001 OK LOGIN completed"),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "IMAP"
    assert any(e.command == "LOGIN" for e in analysis.events)


def test_imap_fragmented_command():
    session = build_session("i3", dst_port=143, script=[])
    session.add_s2c(b"* OK IMAP4rev1 Ready\r\n", 1.0)
    session.add_c2s(b"X1 STAR", 1.1)
    session.add_c2s(b"TTLS\r\n", 1.2)
    analysis = analyze_session(session)
    assert any(e.event_type.value == "STARTTLS_REQUEST" for e in analysis.events)


def test_imap_non_standard_port():
    session = build_session("i4", dst_port=25000, script=[
        ("s2c", b"* OK IMAP4rev1 Ready"),
        ("c2s", b"X1 CAPABILITY"),
        ("s2c", b"* CAPABILITY IMAP4rev1 STARTTLS"),
        ("s2c", b"X1 OK"),
    ])
    analysis = analyze_session(session)
    assert analysis.protocol == "IMAP"
