"""
tests/test_phase7_transition.py

Comprehensive tests for Phase 7: STARTTLS / STLS Transition Analysis.

Tests cover the 10 required scenarios plus additional edge cases:

  1. SMTP STARTTLS success (advertised → requested → accepted → TLS)
  2. SMTP STARTTLS advertised but not used (client goes to AUTH)
  3. SMTP STARTTLS rejected by server (454)
  4. SMTP STARTTLS rejected then auth continues
  5. Implicit TLS (port 465, TLS from first byte)
  6. SMTP STARTTLS accepted + TLS handshake observed
  7. IMAP STARTTLS success
  8. POP3 STLS success
  9. SMTP STARTTLS rejected then AUTH before TLS
 10. Truncated / incomplete PCAP
 11. STARTTLS accepted but no handshake observed
 12. Plaintext session (no STARTTLS, no TLS)
 13. Auth AFTER TLS (correct behavior)
 14. JSON output contract validation
 15. Summary text output
 16. Batch analysis
"""

from __future__ import annotations

import json
import pytest

from app.sessions.manager import SessionManager
from app.sessions.models import EmailSession
from app.transition.analyzer import TLSUpgradeAnalyzer
from app.transition.rules import TransitionStatus, TLSMode


# ═══════════════════════════════════════════════════════════════════
# Helper: build sessions via the SessionManager from Phase 6
# ═══════════════════════════════════════════════════════════════════

def _build_session(
    protocol: str,
    client_stream: bytes,
    server_stream: bytes,
    server_port: int = 587,
    flow_id: str = "FLOW-TEST",
) -> EmailSession:
    """Build a Phase 6 EmailSession from raw streams."""
    mgr = SessionManager()
    return mgr.process_flow(
        flow_id=flow_id,
        protocol=protocol,
        client_ip="192.168.1.10",
        client_port=53422,
        server_ip="10.0.0.5",
        server_port=server_port,
        client_stream=client_stream,
        server_stream=server_stream,
        start_time=1000.0,
    )


TLS_CLIENT_HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40


# ═══════════════════════════════════════════════════════════════════
# Test 1: SMTP STARTTLS Success
# ═══════════════════════════════════════════════════════════════════

class TestSMTPStarttlsSuccess:
    """Case A: STARTTLS advertised → requested → accepted → TLS."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP Postfix\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN PLAIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        client = b"EHLO client.example.com\r\nSTARTTLS\r\n" + TLS_CLIENT_HELLO
        self.session = _build_session("SMTP", client, server)
        self.analyzer = TLSUpgradeAnalyzer()
        self.result = self.analyzer.analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_SUCCESS

    def test_tls_mode(self):
        assert self.result.tls_mode == TLSMode.STARTTLS

    def test_capability_advertised(self):
        assert self.result.capability_advertised is True

    def test_tls_requested(self):
        assert self.result.tls_requested is True

    def test_tls_accepted(self):
        assert self.result.tls_accepted is True

    def test_tls_handshake_observed(self):
        assert self.result.tls_handshake_observed is True

    def test_auth_before_tls_false(self):
        assert self.result.authentication.before_tls is False

    def test_plaintext_after_tls_false(self):
        assert self.result.plaintext_after_tls is False

    def test_confidence_high(self):
        assert self.result.confidence >= 0.70

    def test_evidence_not_empty(self):
        assert len(self.result.evidence) > 0


# ═══════════════════════════════════════════════════════════════════
# Test 2: STARTTLS Advertised But Not Used
# ═══════════════════════════════════════════════════════════════════

class TestStarttlsAvailableNotUsed:
    """Case B: Server offers STARTTLS, client ignores it and goes to AUTH."""

    def setup_method(self):
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
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_AVAILABLE_NOT_USED

    def test_capability_advertised(self):
        assert self.result.capability_advertised is True

    def test_not_requested(self):
        assert self.result.tls_requested is False

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True


# ═══════════════════════════════════════════════════════════════════
# Test 3: STARTTLS Rejected by Server
# ═══════════════════════════════════════════════════════════════════

class TestStarttlsRejected:
    """Case C: Client sends STARTTLS, server responds 454."""

    def setup_method(self):
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
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_REJECTED

    def test_requested(self):
        assert self.result.tls_requested is True

    def test_not_accepted(self):
        assert self.result.tls_accepted is False

    def test_no_handshake(self):
        assert self.result.tls_handshake_observed is False


# ═══════════════════════════════════════════════════════════════════
# Test 4: STARTTLS Rejected Then Auth Continues
# ═══════════════════════════════════════════════════════════════════

class TestStarttlsRejectedThenAuth:
    """Case D: Server rejects STARTTLS, client proceeds with AUTH."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"454 TLS unavailable\r\n"
            b"235 2.7.0 Authentication successful\r\n"
        )
        client = (
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
            b"AUTH LOGIN dXNlcg==\r\n"
        )
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_REJECTED

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True

    def test_tls_not_started(self):
        assert self.result.tls_handshake_observed is False


# ═══════════════════════════════════════════════════════════════════
# Test 5: Implicit TLS
# ═══════════════════════════════════════════════════════════════════

class TestImplicitTLS:
    """Case E: Connection starts directly with TLS (port 465)."""

    def setup_method(self):
        self.session = _build_session(
            "SMTP",
            client_stream=TLS_CLIENT_HELLO,
            server_stream=b"",
            server_port=465,
        )
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.IMPLICIT_TLS

    def test_tls_mode(self):
        assert self.result.tls_mode == TLSMode.IMPLICIT_TLS

    def test_starttls_not_applicable(self):
        # STARTTLS fields should be None (not applicable)
        assert self.result.capability_advertised is None
        assert self.result.tls_requested is None
        assert self.result.tls_accepted is None

    def test_handshake_observed(self):
        assert self.result.tls_handshake_observed is True


# ═══════════════════════════════════════════════════════════════════
# Test 6: STARTTLS Accepted + Full TLS
# ═══════════════════════════════════════════════════════════════════

class TestStarttlsAcceptedWithHandshake:
    """Case F: Full STARTTLS lifecycle with TLS ClientHello + ServerHello."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-SIZE 10240000\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        client = (
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
        ) + TLS_CLIENT_HELLO
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_SUCCESS

    def test_all_lifecycle_steps_true(self):
        assert self.result.capability_advertised is True
        assert self.result.tls_requested is True
        assert self.result.tls_accepted is True
        assert self.result.tls_handshake_observed is True

    def test_confidence_very_high(self):
        assert self.result.confidence >= 0.75


# ═══════════════════════════════════════════════════════════════════
# Test 7: IMAP STARTTLS Success
# ═══════════════════════════════════════════════════════════════════

class TestIMAPStarttlsSuccess:
    """IMAP STARTTLS lifecycle."""

    def setup_method(self):
        server = (
            b"* OK IMAP4rev1 server ready\r\n"
            b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
            b"A001 OK CAPABILITY completed\r\n"
            b"A002 OK Begin TLS negotiation now\r\n"
        )
        client = (
            b"A001 CAPABILITY\r\n"
            b"A002 STARTTLS\r\n"
        ) + TLS_CLIENT_HELLO
        self.session = _build_session("IMAP", client, server, server_port=143)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_SUCCESS

    def test_imap_protocol(self):
        assert self.result.protocol == "IMAP"

    def test_starttls_advertised(self):
        assert self.result.capability_advertised is True

    def test_tls_handshake(self):
        assert self.result.tls_handshake_observed is True


# ═══════════════════════════════════════════════════════════════════
# Test 8: POP3 STLS Success
# ═══════════════════════════════════════════════════════════════════

class TestPOP3StlsSuccess:
    """POP3 STLS lifecycle."""

    def setup_method(self):
        server = (
            b"+OK POP3 server ready\r\n"
            b"+OK Capability list follows\r\n"
            b"STLS\r\n"
            b"USER\r\n"
            b".\r\n"
            b"+OK Begin TLS negotiation\r\n"
        )
        client = (
            b"CAPA\r\n"
            b"STLS\r\n"
        ) + TLS_CLIENT_HELLO
        self.session = _build_session("POP3", client, server, server_port=110)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_SUCCESS

    def test_pop3_protocol(self):
        assert self.result.protocol == "POP3"

    def test_stls_advertised(self):
        assert self.result.capability_advertised is True

    def test_tls_handshake(self):
        assert self.result.tls_handshake_observed is True


# ═══════════════════════════════════════════════════════════════════
# Test 9: STARTTLS Rejected + AUTH Before TLS
# ═══════════════════════════════════════════════════════════════════

class TestRejectedWithAuthBeforeTLS:
    """Combined: rejection + auth in plaintext."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"454 TLS unavailable\r\n"
            b"235 2.7.0 Authentication successful\r\n"
        )
        client = (
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
            b"AUTH LOGIN dXNlcg==\r\n"
        )
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_status_rejected(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_REJECTED

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True

    def test_evidence_has_rejection(self):
        assert any(
            "STARTTLS_REJECTED" in ev.event_type
            for ev in self.result.evidence
        )

    def test_evidence_has_auth_before_tls(self):
        assert any(
            "AUTH_BEFORE_TLS" in ev.event_type
            for ev in self.result.evidence
        )


# ═══════════════════════════════════════════════════════════════════
# Test 10: Incomplete / Truncated Capture
# ═══════════════════════════════════════════════════════════════════

class TestIncompleteCapture:
    """PCAP ends before we can determine the outcome."""

    def setup_method(self):
        # Minimal session — just a greeting, no capabilities, no commands
        server = b"220 mail.example.com ESMTP\r\n"
        client = b"EHLO client.example.com\r\n"
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_no_starttls_advertised(self):
        assert self.result.capability_advertised is False

    def test_no_tls_requested(self):
        assert self.result.tls_requested is False

    def test_status_is_plaintext_or_incomplete(self):
        # Without STARTTLS capability, this is a plaintext session
        assert self.result.transition_status in (
            TransitionStatus.PLAINTEXT_SESSION,
            TransitionStatus.INCOMPLETE_CAPTURE,
        )


# ═══════════════════════════════════════════════════════════════════
# Test 11: STARTTLS Accepted But No Handshake
# ═══════════════════════════════════════════════════════════════════

class TestAcceptedNoHandshake:
    """Server says 220 Ready but no TLS ClientHello follows."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        # Client requests STARTTLS but no TLS bytes follow
        client = (
            b"EHLO client.example.com\r\n"
            b"STARTTLS\r\n"
        )
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_ACCEPTED_NO_HANDSHAKE

    def test_accepted_true(self):
        assert self.result.tls_accepted is True

    def test_handshake_not_observed(self):
        assert self.result.tls_handshake_observed is False


# ═══════════════════════════════════════════════════════════════════
# Test 12: Pure Plaintext Session
# ═══════════════════════════════════════════════════════════════════

class TestPlaintextSession:
    """No STARTTLS, no TLS — pure plaintext."""

    def setup_method(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250 AUTH PLAIN\r\n"
            b"235 2.7.0 Authentication successful\r\n"
            b"250 2.1.0 Ok\r\n"
            b"250 2.1.5 Ok\r\n"
            b"354 End data\r\n"
            b"250 2.0.0 Ok: queued\r\n"
        )
        client = (
            b"EHLO client.example.com\r\n"
            b"AUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n"
            b"MAIL FROM:<sender@example.com>\r\n"
            b"RCPT TO:<recipient@example.com>\r\n"
            b"DATA\r\n"
            b".\r\n"
            b"QUIT\r\n"
        )
        self.session = _build_session("SMTP", client, server)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_transition_status(self):
        assert self.result.transition_status == TransitionStatus.PLAINTEXT_SESSION

    def test_tls_mode_plaintext(self):
        assert self.result.tls_mode == TLSMode.PLAINTEXT

    def test_no_starttls(self):
        assert self.result.capability_advertised is False
        assert self.result.tls_requested is False
        assert self.result.tls_handshake_observed is False

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True


# ═══════════════════════════════════════════════════════════════════
# Test 13: Auth AFTER TLS (Correct Behavior)
# ═══════════════════════════════════════════════════════════════════

class TestAuthAfterTLS:
    """Auth happens after TLS handshake — the correct pattern.
    
    Note: In a STARTTLS flow, after TLS is established the client
    typically re-issues EHLO and then AUTH inside the encrypted tunnel.
    Since our parser stops at the TLS boundary, we can't see post-TLS
    AUTH in the plaintext stream. But if we test with a scenario where
    the Phase 6 security context correctly records it, this validates
    the Phase 7 auth timing logic.
    """

    def test_no_auth_before_tls_on_success(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        client = b"EHLO client.example.com\r\nSTARTTLS\r\n" + TLS_CLIENT_HELLO
        session = _build_session("SMTP", client, server)
        result = TLSUpgradeAnalyzer().analyze(session)

        # No auth events in the plaintext portion
        assert result.authentication.before_tls is False


# ═══════════════════════════════════════════════════════════════════
# Test 14: JSON Output Contract
# ═══════════════════════════════════════════════════════════════════

class TestJSONContract:
    """Verify the Phase 7 JSON output structure."""

    def test_structure(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        client = b"EHLO client.example.com\r\nSTARTTLS\r\n" + TLS_CLIENT_HELLO
        session = _build_session("SMTP", client, server)
        result = TLSUpgradeAnalyzer().analyze(session)
        output = result.to_dict()

        # Top-level keys
        assert "session_id" in output
        assert "protocol" in output
        assert "tls" in output
        assert "evidence" in output
        assert "confidence" in output

        # TLS sub-object
        tls = output["tls"]
        assert "mode" in tls
        assert "capability_advertised" in tls
        assert "requested" in tls
        assert "accepted" in tls
        assert "handshake_observed" in tls
        assert "authentication" in tls
        assert "plaintext_after_tls" in tls
        assert "transition_status" in tls

        # Authentication sub-object
        auth = tls["authentication"]
        assert "before_tls" in auth
        assert "after_tls" in auth

        # Evidence entries
        assert len(output["evidence"]) > 0
        ev = output["evidence"][0]
        assert "type" in ev

        # JSON serializable
        json_str = json.dumps(output, indent=2)
        assert len(json_str) > 0


# ═══════════════════════════════════════════════════════════════════
# Test 15: Summary Text
# ═══════════════════════════════════════════════════════════════════

class TestSummaryText:
    """Verify the CLI summary output."""

    def test_summary_contains_key_info(self):
        server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH LOGIN\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        client = b"EHLO client.example.com\r\nSTARTTLS\r\n" + TLS_CLIENT_HELLO
        session = _build_session("SMTP", client, server)
        result = TLSUpgradeAnalyzer().analyze(session)
        summary = result.summary()

        assert "PHASE 7" in summary
        assert "SMTP" in summary
        assert "STARTTLS" in summary
        assert "YES" in summary
        assert "Transition Status" in summary


# ═══════════════════════════════════════════════════════════════════
# Test 16: Batch Analysis
# ═══════════════════════════════════════════════════════════════════

class TestBatchAnalysis:
    """Multiple sessions analyzed in batch."""

    def test_batch_returns_correct_count(self):
        sessions = []
        mgr = SessionManager()

        # Session 1: STARTTLS success
        s1_server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250-STARTTLS\r\n"
            b"250 AUTH\r\n"
            b"220 Ready to start TLS\r\n"
        )
        s1_client = b"EHLO c\r\nSTARTTLS\r\n" + TLS_CLIENT_HELLO
        sessions.append(mgr.process_flow(
            "F1", "SMTP", "1.1.1.1", 1111, "2.2.2.2", 587,
            s1_client, s1_server, 1000.0,
        ))

        # Session 2: Plaintext
        s2_server = (
            b"220 mail.example.com ESMTP\r\n"
            b"250 AUTH PLAIN\r\n"
            b"235 OK\r\n"
        )
        s2_client = b"EHLO c\r\nAUTH PLAIN x\r\n"
        sessions.append(mgr.process_flow(
            "F2", "SMTP", "3.3.3.3", 2222, "4.4.4.4", 25,
            s2_client, s2_server, 2000.0,
        ))

        analyzer = TLSUpgradeAnalyzer()
        results = analyzer.analyze_batch(sessions)

        assert len(results) == 2
        assert results[0].transition_status == TransitionStatus.STARTTLS_SUCCESS
        assert results[1].transition_status == TransitionStatus.PLAINTEXT_SESSION


# ═══════════════════════════════════════════════════════════════════
# Test 17: IMAP Plaintext LOGIN (No TLS)
# ═══════════════════════════════════════════════════════════════════

class TestIMAPPlaintextLogin:
    """IMAP LOGIN without TLS — auth before TLS detected."""

    def setup_method(self):
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
        self.session = _build_session("IMAP", client, server, server_port=143)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_starttls_available_not_used(self):
        assert self.result.transition_status == TransitionStatus.STARTTLS_AVAILABLE_NOT_USED

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True


# ═══════════════════════════════════════════════════════════════════
# Test 18: POP3 Plaintext Auth (No TLS)
# ═══════════════════════════════════════════════════════════════════

class TestPOP3PlaintextAuth:
    """POP3 USER/PASS without TLS."""

    def setup_method(self):
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
        self.session = _build_session("POP3", client, server, server_port=110)
        self.result = TLSUpgradeAnalyzer().analyze(self.session)

    def test_no_starttls(self):
        assert self.result.capability_advertised is False

    def test_auth_before_tls(self):
        assert self.result.authentication.before_tls is True

    def test_plaintext_session(self):
        assert self.result.transition_status == TransitionStatus.PLAINTEXT_SESSION
