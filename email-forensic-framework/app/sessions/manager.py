"""
app/sessions/manager.py

Session Manager — the orchestrator for Phase 6.

Associates TCP flows with email sessions, drives the protocol
parsers and state machines, and produces the final EmailSession
objects (Phase 6 output).

Architecture:

    ReconstructedSession (Phase 5)
           ↓
    SessionManager.process_flow()
           ↓
    ┌──────────────────────────────┐
    │ 1. Protocol detection        │  (reuses app/protocol/classifier)
    │ 2. Event parsing             │  (app/sessions/smtp|imap|pop3/events)
    │ 3. State machine execution   │  (app/sessions/state_machine)
    │ 4. Security context assembly │
    └──────────────────────────────┘
           ↓
    EmailSession (Phase 6 output)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from app.sessions.models import EmailSession, SecurityContext
from app.sessions.state_machine import (
    create_state_machine,
    SMTPSessionStateMachine,
    IMAPSessionStateMachine,
    POP3SessionStateMachine,
)
from app.sessions.smtp.events import parse_smtp_streams
from app.sessions.imap.events import parse_imap_streams
from app.sessions.pop3.events import parse_pop3_streams
from app.protocol.common import looks_like_tls_record


class SessionManager:
    """
    Manages the lifecycle of email sessions.

    Usage:

        manager = SessionManager()

        # Process a TCP flow that has been reconstructed by Phase 5
        session = manager.process_flow(
            flow_id="FLOW-00001",
            protocol="SMTP",
            client_ip="192.168.1.10",
            client_port=53422,
            server_ip="10.0.0.5",
            server_port=587,
            client_stream=b"EHLO mail.example.com\\r\\n...",
            server_stream=b"220 mail.example.com ESMTP\\r\\n...",
            start_time=1758754301.0,
        )

        print(session.summary())
        print(json.dumps(session.to_dict(), indent=2))
    """

    def __init__(self) -> None:
        self.sessions: dict[str, EmailSession] = {}
        self._session_counter: int = 0

    def _next_session_id(self, protocol: str) -> str:
        self._session_counter += 1
        return f"{protocol}-{self._session_counter:05d}"

    def process_flow(
        self,
        flow_id: str,
        protocol: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        client_stream: bytes,
        server_stream: bytes,
        start_time: Optional[float] = None,
    ) -> EmailSession:
        """
        Build a complete EmailSession from a reconstructed TCP flow.

        Args:
            flow_id:        Unique identifier from Phase 5's flow manager.
            protocol:       Detected protocol ("SMTP", "IMAP", "POP3").
            client_ip:      Client IP address.
            client_port:    Client ephemeral port.
            server_ip:      Server IP address.
            server_port:    Server listening port.
            client_stream:  Reassembled client-to-server byte stream.
            server_stream:  Reassembled server-to-client byte stream.
            start_time:     Epoch timestamp of the first packet.

        Returns:
            A fully populated EmailSession.
        """
        if start_time is None:
            start_time = time.time()

        proto = protocol.upper()
        session_id = self._next_session_id(proto)

        # ── 1. Create the session object ──
        session = EmailSession(
            session_id=session_id,
            protocol=proto,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
        )

        # ── 2. Detect implicit TLS (ports 465, 993, 995) ──
        if self._is_implicit_tls(client_stream, server_port):
            from app.sessions.models import SessionEvent
            session.mode = "IMPLICIT_TLS"
            session.security.tls_started = True
            implicit_event = SessionEvent(
                timestamp=start_time,
                direction="client_to_server",
                event_type="IMPLICIT_TLS",
                raw_data="[Implicit TLS — connection starts encrypted]",
                stream_offset=0,
            )
            session.add_event(implicit_event)
            session.state = "ENCRYPTED"
            self.sessions[session_id] = session
            return session

        # ── 3. Parse protocol events from streams ──
        events = self._parse_events(proto, client_stream, server_stream, start_time)

        if not events:
            session.parse_warnings.append(
                "No protocol events detected in stream data"
            )
            self.sessions[session_id] = session
            return session

        # ── 4. Create and run the state machine ──
        try:
            sm = create_state_machine(proto)
        except ValueError as exc:
            session.parse_warnings.append(str(exc))
            # Still add events even without a state machine
            for event in events:
                session.add_event(event)
            self.sessions[session_id] = session
            return session

        for event in events:
            session.add_event(event)
            sm.process_event(session, event)

        # ── 5. Store and return ──
        self.sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[EmailSession]:
        return self.sessions.get(session_id)

    def all_sessions(self) -> list[EmailSession]:
        return list(self.sessions.values())

    def export_session(self, session_id: str) -> Optional[dict]:
        """Export a single session as a JSON-serializable dict."""
        session = self.sessions.get(session_id)
        if session:
            return session.to_dict()
        return None

    def export_all(self) -> list[dict]:
        """Export all sessions."""
        return [s.to_dict() for s in self.sessions.values()]

    def export_to_file(self, session_id: str, output_dir: Path) -> Path:
        """Write a session's JSON to disk and return the filepath."""
        output_dir.mkdir(parents=True, exist_ok=True)
        session = self.sessions[session_id]
        path = output_dir / f"{session_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(session.to_dict(), f, indent=2)
        return path

    def export_all_to_dir(self, output_dir: Path) -> list[Path]:
        """Write all sessions to a directory."""
        paths = []
        for sid in self.sessions:
            paths.append(self.export_to_file(sid, output_dir))
        return paths

    # ── Private helpers ──

    @staticmethod
    def _is_implicit_tls(client_stream: bytes, server_port: int) -> bool:
        """
        Detect implicit TLS: the connection starts with a TLS handshake
        (common on ports 465, 993, 995).
        """
        implicit_ports = {465, 993, 995}
        if server_port in implicit_ports and looks_like_tls_record(client_stream):
            return True
        # Even on non-standard ports, if the very first bytes are TLS...
        if looks_like_tls_record(client_stream):
            return True
        return False

    @staticmethod
    def _parse_events(
        protocol: str,
        client_stream: bytes,
        server_stream: bytes,
        start_time: float,
    ):
        """Dispatch to the correct protocol event parser."""
        if protocol == "SMTP":
            return parse_smtp_streams(client_stream, server_stream, start_time)
        elif protocol == "IMAP":
            return parse_imap_streams(client_stream, server_stream, start_time)
        elif protocol == "POP3":
            return parse_pop3_streams(client_stream, server_stream, start_time)
        else:
            return []
