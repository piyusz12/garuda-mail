"""
tests/test_phase6_sessions.py

Comprehensive tests for Phase 6: Stateful Email Session Engine.

Tests cover:
  1. SMTP with successful STARTTLS upgrade
  2. SMTP with STARTTLS rejection → plaintext continuation
  3. SMTP with STARTTLS advertised but never requested
  4. SMTP with authentication before TLS (security concern)
  5. SMTP full mail transaction after TLS
  6. IMAP with STARTTLS upgrade
  7. IMAP with plaintext LOGIN (no TLS)
  8. POP3 with STLS upgrade
  9. POP3 with plaintext USER/PASS (no TLS)
 10. Session Manager orchestration
 11. JSON export contract validation
"""

from __future__ import annotations

import json
import time
import pytest

from app.sessions.models import EmailSession, SessionEvent, SecurityContext
from app.sessions.state_machine import (
    SMTPSessionStateMachine,
    IMAPSessionStateMachine,
    POP3SessionStateMachine,
    create_state_machine,
)
from app.sessions.smtp.events import (
    parse_smtp_server_stream,
    parse_smtp_client_stream,
    parse_smtp_streams,
)
from app.sessions.imap.events import parse_imap_streams
from app.sessions.pop3.events import parse_pop3_streams
from app.sessions.manager import SessionManager


# ═══════════════════════════════════════════════════════════════════
# Fixtures — synthetic SMTP / IMAP / POP3 conversations
# ═══════════════════════════════════════════════════════════════════

def _smtp_starttls_success_streams():
    """SMTP conversation with successful STARTTLS upgrade."""
    server = (
        b"220 mail.example.com ESMTP Postfix\r\n"
        b"250-mail.example.com\r\n"
        b"250-PIPELINING\r\n"
        b"250-SIZE 10240000\r\n"
        b"250-STARTTLS\r\n"
        b"250-AUTH LOGIN PLAIN\r\n"
        b"250 8BITMIME\r\n"
        b"220 2.0.0 Ready to start TLS\r\n"
    )
    # After "220 Ready to start TLS", client sends TLS ClientHello
    tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40
    client = (
        b"EHLO client.example.com\r\n"
        b"STARTTLS\r\n"
    ) + tls_hello
    return client, server


def _smtp_starttls_rejected_streams():
    """SMTP where server rejects STARTTLS with 454."""
    server = (
        b"220 mail.example.com ESMTP\r\n"
        b"250-mail.example.com\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH LOGIN\r\n"
        b"454 TLS not available due to temporary reason\r\n"
    )
    client = (
        b"EHLO client.example.com\r\n"
        b"STARTTLS\r\n"
    )
    return client, server


def _smtp_starttls_advertised_not_requested():
    """SMTP where STARTTLS is advertised but client goes straight to AUTH."""
    server = (
        b"220 mail.example.com ESMTP\r\n"
        b"250-mail.example.com\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH LOGIN PLAIN\r\n"
        b"535 5.7.8 Error: authentication failed\r\n"
    )
    client = (
        b"EHLO client.example.com\r\n"
        b"AUTH LOGIN dXNlcg==\r\n"
    )
    return client, server


def _smtp_auth_before_tls_streams():
    """SMTP where client authenticates before upgrading to TLS."""
    server = (
        b"220 mail.example.com ESMTP\r\n"
        b"250-mail.example.com\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH PLAIN\r\n"
        b"235 2.7.0 Authentication successful\r\n"
    )
    client = (
        b"EHLO client.example.com\r\n"
        b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
    )
    return client, server


def _smtp_full_transaction_streams():
    """SMTP with a complete mail transaction (no STARTTLS)."""
    server = (
        b"220 mail.example.com ESMTP\r\n"
        b"250-mail.example.com\r\n"
        b"250 AUTH PLAIN\r\n"
        b"235 2.7.0 Authentication successful\r\n"
        b"250 2.1.0 Ok\r\n"
        b"250 2.1.5 Ok\r\n"
        b"354 End data with <CR><LF>.<CR><LF>\r\n"
        b"250 2.0.0 Ok: queued\r\n"
    )
    client = (
        b"EHLO client.example.com\r\n"
        b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
        b"MAIL FROM:<sender@example.com>\r\n"
        b"RCPT TO:<recipient@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: Test\r\n"
        b"\r\n"
        b"Hello!\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    return client, server


def _imap_starttls_streams():
    """IMAP conversation with STARTTLS upgrade."""
    server = (
        b"* OK IMAP4rev1 server ready\r\n"
        b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
        b"A001 OK CAPABILITY completed\r\n"
        b"A002 OK Begin TLS negotiation now\r\n"
    )
    tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40
    client = (
        b"A001 CAPABILITY\r\n"
        b"A002 STARTTLS\r\n"
    ) + tls_hello
    return client, server


def _imap_plaintext_login_streams():
    """IMAP with plaintext LOGIN (no TLS)."""
    server = (
        b"* OK IMAP4rev1 server ready\r\n"
        b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
        b"A001 OK CAPABILITY completed\r\n"
        b"A002 OK LOGIN completed\r\n"
    )
    client = (
        b"A001 CAPABILITY\r\n"
        b"A002 LOGIN user password\r\n"
    )
    return client, server


def _pop3_stls_streams():
    """POP3 conversation with STLS upgrade."""
    server = (
        b"+OK POP3 server ready\r\n"
        b"+OK Capability list follows\r\n"
        b"STLS\r\n"
        b"USER\r\n"
        b".\r\n"
        b"+OK Begin TLS negotiation\r\n"
    )
    tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40
    client = (
        b"CAPA\r\n"
        b"STLS\r\n"
    ) + tls_hello
    return client, server


def _pop3_plaintext_auth_streams():
    """POP3 with plaintext USER/PASS (no TLS)."""
    server = (
        b"+OK POP3 server ready\r\n"
        b"+OK\r\n"
        b"+OK Logged in\r\n"
    )
    client = (
        b"USER admin\r\n"
        b"PASS secret123\r\n"
        b"QUIT\r\n"
    )
    return client, server


# ═══════════════════════════════════════════════════════════════════
# Test: SMTP Event Parsing
# ═══════════════════════════════════════════════════════════════════

class TestSMTPEventParsing:
    """Tests for the SMTP event parser (stream → events)."""

    def test_server_greeting_detected(self):
        server = b"220 mail.example.com ESMTP Postfix\r\n"
        events = parse_smtp_server_stream(server, 1000.0)
        assert any(e.event_type == "SMTP_GREETING" for e in events)

    def test_starttls_advertised_detected(self):
        server = b"250-STARTTLS\r\n"
        events = parse_smtp_server_stream(server, 1000.0)
        assert any(e.event_type == "STARTTLS_ADVERTISED" for e in events)

    def test_starttls_accept_detected(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        events = parse_smtp_server_stream(server, 1000.0)
        assert any(e.event_type == "STARTTLS_ACCEPTED" for e in events)

    def test_starttls_reject_detected(self):
        server = b"454 TLS not available\r\n"
        events = parse_smtp_server_stream(server, 1000.0)
        assert any(e.event_type == "STARTTLS_REJECTED" for e in events)

    def test_ehlo_detected(self):
        client = b"EHLO client.example.com\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "EHLO" for e in events)

    def test_starttls_command_detected(self):
        client = b"STARTTLS\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "STARTTLS_REQUESTED" for e in events)

    def test_auth_command_detected(self):
        client = b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        auth_events = [e for e in events if e.event_type == "AUTH_ATTEMPT"]
        assert len(auth_events) == 1
        assert auth_events[0].raw_data == "PLAIN"  # Credential redacted

    def test_mail_from_detected(self):
        client = b"MAIL FROM:<sender@example.com>\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "MAIL_FROM" for e in events)

    def test_rcpt_to_detected(self):
        client = b"RCPT TO:<recipient@example.com>\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "RCPT_TO" for e in events)

    def test_data_command_detected(self):
        client = b"DATA\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "DATA_START" for e in events)

    def test_quit_detected(self):
        client = b"QUIT\r\n"
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "QUIT" for e in events)

    def test_tls_boundary_detected(self):
        tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40
        client = b"STARTTLS\r\n" + tls_hello
        events = parse_smtp_client_stream(client, 1000.0)
        assert any(e.event_type == "TLS_HANDSHAKE_STARTED" for e in events)

    def test_merged_event_stream_ordering(self):
        client, server = _smtp_starttls_success_streams()
        events = parse_smtp_streams(client, server, 1000.0)
        # Events should be time-ordered
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)
        # Should contain both server and client events
        directions = {e.direction for e in events}
        assert "server_to_client" in directions
        assert "client_to_server" in directions


# ═══════════════════════════════════════════════════════════════════
# Test: SMTP State Machine
# ═══════════════════════════════════════════════════════════════════

class TestSMTPStateMachine:
    """Tests for the SMTP state machine transitions."""

    def _make_session(self) -> EmailSession:
        return EmailSession(
            session_id="TEST-SMTP-001",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53422,
            server_ip="10.0.0.5",
            server_port=587,
        )

    def test_greeting_transition(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()
        event = SessionEvent(timestamp=1.0, direction="s2c",
                             event_type="SMTP_GREETING")
        sm.process_event(session, event)
        assert session.state == "SMTP_GREETING"

    def test_ehlo_transition(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()
        session.state = "SMTP_GREETING"
        event = SessionEvent(timestamp=2.0, direction="c2s",
                             event_type="EHLO")
        sm.process_event(session, event)
        assert session.state == "EHLO_HELO"

    def test_starttls_full_lifecycle(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()

        events = [
            SessionEvent(timestamp=1.0, direction="s2c",
                         event_type="SMTP_GREETING"),
            SessionEvent(timestamp=2.0, direction="c2s",
                         event_type="EHLO"),
            SessionEvent(timestamp=3.0, direction="s2c",
                         event_type="CAPABILITY_RESPONSE"),
            SessionEvent(timestamp=3.1, direction="s2c",
                         event_type="STARTTLS_ADVERTISED"),
            SessionEvent(timestamp=4.0, direction="c2s",
                         event_type="STARTTLS_REQUESTED"),
            SessionEvent(timestamp=5.0, direction="s2c",
                         event_type="STARTTLS_ACCEPTED"),
            SessionEvent(timestamp=6.0, direction="c2s",
                         event_type="TLS_HANDSHAKE_STARTED"),
        ]

        for e in events:
            sm.process_event(session, e)

        assert session.state == "TLS_HANDSHAKE"
        assert session.security.starttls_advertised is True
        assert session.security.starttls_requested is True
        assert session.security.starttls_accepted is True
        assert session.security.tls_started is True
        assert session.mode == "TLS"

    def test_starttls_rejection(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()
        session.state = "STARTTLS_REQUESTED"
        session.security.starttls_requested = True

        event = SessionEvent(timestamp=5.0, direction="s2c",
                             event_type="STARTTLS_REJECTED")
        sm.process_event(session, event)

        assert session.state == "STARTTLS_REJECTED"
        assert session.security.starttls_rejected is True
        assert session.security.tls_started is False

    def test_auth_before_tls_detected(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()
        session.state = "CAPABILITY_RESPONSE"

        event = SessionEvent(timestamp=4.0, direction="c2s",
                             event_type="AUTH_ATTEMPT",
                             raw_data="LOGIN")
        sm.process_event(session, event)

        assert session.state == "AUTHENTICATION"
        assert session.security.authentication_attempted is True
        assert session.security.authentication_before_tls is True

    def test_quit_closes_session(self):
        sm = SMTPSessionStateMachine()
        session = self._make_session()
        session.state = "MAIL_TRANSACTION"
        event = SessionEvent(timestamp=10.0, direction="c2s",
                             event_type="QUIT")
        sm.process_event(session, event)
        assert session.state == "CLOSED"


# ═══════════════════════════════════════════════════════════════════
# Test: Session Manager (End-to-End)
# ═══════════════════════════════════════════════════════════════════

class TestSessionManager:
    """Integration tests for the SessionManager orchestrator."""

    def test_smtp_starttls_success(self):
        manager = SessionManager()
        client, server = _smtp_starttls_success_streams()

        session = manager.process_flow(
            flow_id="FLOW-00001",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53422,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.protocol == "SMTP"
        assert session.security.starttls_advertised is True
        assert session.security.starttls_requested is True
        assert session.security.starttls_accepted is True
        assert session.security.tls_started is True
        assert session.security.authentication_before_tls is False
        assert session.state == "TLS_HANDSHAKE"
        assert len(session.events) > 0

    def test_smtp_starttls_rejected(self):
        manager = SessionManager()
        client, server = _smtp_starttls_rejected_streams()

        session = manager.process_flow(
            flow_id="FLOW-00002",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53423,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.starttls_requested is True
        assert session.security.starttls_rejected is True
        assert session.security.tls_started is False

    def test_smtp_starttls_advertised_not_requested(self):
        manager = SessionManager()
        client, server = _smtp_starttls_advertised_not_requested()

        session = manager.process_flow(
            flow_id="FLOW-00003",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53424,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.starttls_advertised is True
        assert session.security.starttls_requested is False

    def test_smtp_auth_before_tls(self):
        manager = SessionManager()
        client, server = _smtp_auth_before_tls_streams()

        session = manager.process_flow(
            flow_id="FLOW-00004",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53425,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.authentication_attempted is True
        assert session.security.authentication_before_tls is True
        assert session.security.starttls_advertised is True
        assert session.security.tls_started is False

    def test_smtp_full_transaction(self):
        manager = SessionManager()
        client, server = _smtp_full_transaction_streams()

        session = manager.process_flow(
            flow_id="FLOW-00005",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53426,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.authentication_attempted is True
        assert session.security.mail_from is not None
        assert len(session.security.rcpt_to) > 0
        assert session.security.data_started is True
        assert session.state == "CLOSED"

    def test_imap_starttls(self):
        manager = SessionManager()
        client, server = _imap_starttls_streams()

        session = manager.process_flow(
            flow_id="FLOW-00006",
            protocol="IMAP",
            client_ip="192.168.1.10",
            client_port=53427,
            server_ip="10.0.0.5",
            server_port=143,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.protocol == "IMAP"
        assert session.security.starttls_advertised is True
        assert session.security.starttls_requested is True
        assert session.security.starttls_accepted is True
        assert session.security.tls_started is True

    def test_imap_plaintext_login(self):
        manager = SessionManager()
        client, server = _imap_plaintext_login_streams()

        session = manager.process_flow(
            flow_id="FLOW-00007",
            protocol="IMAP",
            client_ip="192.168.1.10",
            client_port=53428,
            server_ip="10.0.0.5",
            server_port=143,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.authentication_attempted is True
        assert session.security.authentication_before_tls is True
        assert session.security.tls_started is False

    def test_pop3_stls(self):
        manager = SessionManager()
        client, server = _pop3_stls_streams()

        session = manager.process_flow(
            flow_id="FLOW-00008",
            protocol="POP3",
            client_ip="192.168.1.10",
            client_port=53429,
            server_ip="10.0.0.5",
            server_port=110,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.protocol == "POP3"
        assert session.security.starttls_advertised is True
        assert session.security.starttls_requested is True
        assert session.security.starttls_accepted is True
        assert session.security.tls_started is True

    def test_pop3_plaintext_auth(self):
        manager = SessionManager()
        client, server = _pop3_plaintext_auth_streams()

        session = manager.process_flow(
            flow_id="FLOW-00009",
            protocol="POP3",
            client_ip="192.168.1.10",
            client_port=53430,
            server_ip="10.0.0.5",
            server_port=110,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        assert session.security.authentication_attempted is True
        assert session.security.authentication_before_tls is True
        assert session.security.tls_started is False


# ═══════════════════════════════════════════════════════════════════
# Test: JSON Export Contract
# ═══════════════════════════════════════════════════════════════════

class TestJSONExport:
    """Verify the Phase 6 output contract."""

    def test_export_structure(self):
        manager = SessionManager()
        client, server = _smtp_starttls_success_streams()

        session = manager.process_flow(
            flow_id="FLOW-00001",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53422,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        output = session.to_dict()

        # Top-level keys
        assert "session_id" in output
        assert "protocol" in output
        assert "client" in output
        assert "server" in output
        assert "state" in output
        assert "events" in output
        assert "security_context" in output

        # Client/server structure
        assert "ip" in output["client"]
        assert "port" in output["client"]
        assert "ip" in output["server"]
        assert "port" in output["server"]

        # Security context keys
        sec = output["security_context"]
        assert "starttls_advertised" in sec
        assert "starttls_requested" in sec
        assert "starttls_accepted" in sec
        assert "tls_started" in sec
        assert "authentication_before_tls" in sec

        # Events structure
        assert len(output["events"]) > 0
        event = output["events"][0]
        assert "type" in event
        assert "direction" in event
        assert "timestamp" in event

        # Should be JSON serializable
        json_str = json.dumps(output, indent=2)
        assert len(json_str) > 0

    def test_session_summary_text(self):
        manager = SessionManager()
        client, server = _smtp_starttls_success_streams()

        session = manager.process_flow(
            flow_id="FLOW-00001",
            protocol="SMTP",
            client_ip="192.168.1.20",
            client_port=49152,
            server_ip="10.0.0.10",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        summary = session.summary()
        assert "EMAIL SESSION" in summary
        assert "SMTP" in summary
        assert "192.168.1.20" in summary
        assert "STARTTLS advertised" in summary
        assert "YES" in summary


# ═══════════════════════════════════════════════════════════════════
# Test: State Machine Factory
# ═══════════════════════════════════════════════════════════════════

class TestStateMachineFactory:

    def test_smtp_factory(self):
        sm = create_state_machine("SMTP")
        assert isinstance(sm, SMTPSessionStateMachine)

    def test_imap_factory(self):
        sm = create_state_machine("IMAP")
        assert isinstance(sm, IMAPSessionStateMachine)

    def test_pop3_factory(self):
        sm = create_state_machine("POP3")
        assert isinstance(sm, POP3SessionStateMachine)

    def test_unknown_protocol_raises(self):
        with pytest.raises(ValueError):
            create_state_machine("FTP")


# ═══════════════════════════════════════════════════════════════════
# Test: Session Timeline
# ═══════════════════════════════════════════════════════════════════

class TestSessionTimeline:

    def test_timeline_generation(self):
        manager = SessionManager()
        client, server = _smtp_starttls_success_streams()

        session = manager.process_flow(
            flow_id="FLOW-00001",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53422,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=client,
            server_stream=server,
            start_time=1000.0,
        )

        timeline = session.timeline
        assert len(timeline) > 0
        # Each line should contain an event type
        event_types_in_timeline = [line.split()[-1] for line in timeline]
        assert "SMTP_GREETING" in event_types_in_timeline

    def test_duration_calculation(self):
        session = EmailSession(
            session_id="TEST",
            protocol="SMTP",
            client_ip="1.2.3.4",
            client_port=1234,
            server_ip="5.6.7.8",
            server_port=587,
        )
        session.add_event(SessionEvent(timestamp=1000.0, direction="s2c",
                                       event_type="GREETING"))
        session.add_event(SessionEvent(timestamp=1000.5, direction="c2s",
                                       event_type="EHLO"))
        assert session.duration_ms == pytest.approx(500.0, abs=1.0)
