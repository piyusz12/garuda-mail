from app.protocol.detector import analyze_session
from app.protocol.common import looks_like_tls_record
from tests.fixtures import TLS_CLIENT_HELLO_BYTES, build_session


def test_exact_tls_boundary_offset_and_direction():
    session = build_session("b1", dst_port=587, script=[
        ("s2c", b"220 mail.example.com ESMTP"),
        ("c2s", b"EHLO workstation.local"),
        ("s2c", b"250-STARTTLS"),
        ("c2s", b"STARTTLS"),
        ("s2c", b"220 2.0.0 Ready to start TLS"),
        ("c2s", TLS_CLIENT_HELLO_BYTES),
    ])
    analysis = analyze_session(session)
    enc = analysis.encryption
    boundary = enc["boundary"]
    assert boundary is not None
    assert boundary["direction"] == "client_to_server"

    offset = boundary["offset"]
    stream = session.client_to_server
    bytes_before = stream[:offset]
    bytes_at_boundary = stream[offset:]

    # Everything before the boundary must be plaintext SMTP commands.
    assert b"EHLO" in bytes_before
    assert b"STARTTLS" in bytes_before
    assert not looks_like_tls_record(bytes_before)

    # The boundary itself must be exactly where the TLS record begins.
    assert looks_like_tls_record(bytes_at_boundary)
    assert bytes_at_boundary.startswith(TLS_CLIENT_HELLO_BYTES)


def test_implicit_tls_when_hello_is_first_bytes():
    session = build_session("b2", dst_port=465, script=[
        ("c2s", TLS_CLIENT_HELLO_BYTES),
    ])
    analysis = analyze_session(session)
    # No plaintext SMTP signatures present, so classification stays UNKNOWN,
    # but the encryption engine should still recognize implicit TLS if a
    # protocol *were* identified. Directly exercise the boundary logic:
    from app.encryption.tls_boundary import find_tls_client_hello, is_implicit_tls
    from app.protocol.smtp.parser import SMTPParser

    parser = SMTPParser()
    parsed = parser.parse(session)
    hello = find_tls_client_hello(parsed["events"])
    assert hello is not None
    assert is_implicit_tls(hello, parsed["events"]) is True
