"""
app/sessions/state_machine.py

Generic state-machine infrastructure for Phase 6.

Each protocol (SMTP, IMAP, POP3) defines its own concrete state
machine by subclassing `ProtocolStateMachine` and implementing
`process_event`.  The base class provides common bookkeeping:
transition logging, illegal-transition warnings, and terminal
state detection.

Design note:
  The old per-protocol state machines (app/protocol/*/state_machine.py)
  were small enums + explicit method calls.  This new version is
  *event-driven*: it consumes SessionEvent objects from the parsers,
  making the architecture data-flow rather than call-flow.
  The old state machines remain in place for backward compatibility
  with the Phase 2/3 pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.sessions.models import EmailSession, SessionEvent


class StateTransition:
    """Records a single state change for audit / debugging."""

    __slots__ = ("from_state", "to_state", "trigger_event", "timestamp")

    def __init__(
        self,
        from_state: str,
        to_state: str,
        trigger_event: str,
        timestamp: float,
    ) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.trigger_event = trigger_event
        self.timestamp = timestamp

    def __repr__(self) -> str:
        return (
            f"StateTransition({self.from_state!r} → {self.to_state!r} "
            f"via {self.trigger_event!r})"
        )


class ProtocolStateMachine(ABC):
    """
    Base class for protocol-specific state machines.

    Subclasses implement `process_event` and call `_transition` to
    move the session to a new state.
    """

    def __init__(self) -> None:
        self.transitions: list[StateTransition] = []

    # ── subclass API ──

    @property
    @abstractmethod
    def valid_states(self) -> set[str]:
        """Return the complete set of legal state names."""

    @property
    @abstractmethod
    def terminal_states(self) -> set[str]:
        """States from which no further transitions are expected."""

    @abstractmethod
    def process_event(self, session: EmailSession, event: SessionEvent) -> None:
        """
        Inspect `event` and mutate `session.state` / `session.security`
        accordingly.  Call `self._transition(session, new_state, event)`
        to record the state change.
        """

    # ── shared helpers ──

    def _transition(
        self,
        session: EmailSession,
        new_state: str,
        event: SessionEvent,
    ) -> None:
        """
        Move `session` to `new_state` and log the transition.

        If `new_state` isn't in `valid_states`, the transition still
        happens but a parse warning is recorded.
        """
        old = session.state

        if new_state not in self.valid_states:
            session.parse_warnings.append(
                f"Unexpected state '{new_state}' "
                f"(triggered by {event.event_type})"
            )

        self.transitions.append(
            StateTransition(old, new_state, event.event_type, event.timestamp)
        )
        session.state = new_state

    def is_terminal(self, session: EmailSession) -> bool:
        return session.state in self.terminal_states


# ─── SMTP State Machine ────────────────────────────────────────────

SMTP_STATES = {
    "TCP_CONNECTED",
    "SMTP_GREETING",
    "EHLO_HELO",
    "CAPABILITY_RESPONSE",
    "STARTTLS_REQUESTED",
    "STARTTLS_ACCEPTED",
    "STARTTLS_REJECTED",
    "TLS_HANDSHAKE",
    "ENCRYPTED",
    "AUTHENTICATION",
    "AUTH_SUCCESS",
    "AUTH_FAILED",
    "MAIL_TRANSACTION",
    "DATA_TRANSFER",
    "CLOSED",
    "ERROR",
}

SMTP_TERMINAL = {"CLOSED", "ERROR", "ENCRYPTED"}


class SMTPSessionStateMachine(ProtocolStateMachine):
    """
    Event-driven SMTP state machine for Phase 6.

    Handles the full SMTP conversation lifecycle including:
    - Greeting → EHLO/HELO → Capability negotiation
    - STARTTLS upgrade (success / rejection / skipped)
    - Authentication tracking (especially pre-TLS auth)
    - MAIL FROM / RCPT TO / DATA transaction tracking
    - QUIT / connection close

    State transitions are driven by SessionEvent objects produced
    by the SMTP event parser (app/sessions/smtp/events.py).
    """

    @property
    def valid_states(self) -> set[str]:
        return SMTP_STATES

    @property
    def terminal_states(self) -> set[str]:
        return SMTP_TERMINAL

    def process_event(self, session: EmailSession, event: SessionEvent) -> None:
        etype = event.event_type
        state = session.state
        sec = session.security

        # ── Server greeting ──
        if etype == "SMTP_GREETING":
            if state == "TCP_CONNECTED":
                self._transition(session, "SMTP_GREETING", event)

        # ── Client EHLO / HELO ──
        elif etype == "EHLO" or etype == "HELO":
            if state in ("SMTP_GREETING", "TCP_CONNECTED"):
                self._transition(session, "EHLO_HELO", event)

        # ── Server capability response (250) ──
        elif etype == "CAPABILITY_RESPONSE":
            if state == "EHLO_HELO":
                self._transition(session, "CAPABILITY_RESPONSE", event)

        # ── STARTTLS advertised in capabilities ──
        elif etype == "STARTTLS_ADVERTISED":
            sec.starttls_advertised = True
            # Don't change state — it's part of the capability block

        # ── Other capabilities advertised ──
        elif etype == "CAPABILITY_ITEM":
            # Track what the server offers (AUTH mechanisms, etc.)
            cap = event.raw_data.strip()
            if cap and cap not in sec.advertised_capabilities:
                sec.advertised_capabilities.append(cap)

        # ── Client requests STARTTLS ──
        elif etype == "STARTTLS_REQUESTED":
            sec.starttls_requested = True
            if state in ("CAPABILITY_RESPONSE", "EHLO_HELO"):
                self._transition(session, "STARTTLS_REQUESTED", event)

        # ── Server accepts STARTTLS (220 Ready) ──
        elif etype == "STARTTLS_ACCEPTED":
            sec.starttls_accepted = True
            if state == "STARTTLS_REQUESTED":
                self._transition(session, "STARTTLS_ACCEPTED", event)

        # ── Server rejects STARTTLS (454 / 5xx) ──
        elif etype == "STARTTLS_REJECTED":
            sec.starttls_rejected = True
            if state == "STARTTLS_REQUESTED":
                self._transition(session, "STARTTLS_REJECTED", event)

        # ── TLS ClientHello detected → handshake started ──
        elif etype == "TLS_HANDSHAKE_STARTED":
            sec.tls_started = True
            session.mode = "TLS"
            if state in ("STARTTLS_ACCEPTED", "STARTTLS_REQUESTED", "TCP_CONNECTED"):
                self._transition(session, "TLS_HANDSHAKE", event)

        # ── TLS fully established (heuristic: first app-data after handshake) ──
        elif etype == "ENCRYPTED_TRAFFIC":
            session.mode = "TLS"
            if state == "TLS_HANDSHAKE":
                self._transition(session, "ENCRYPTED", event)

        # ── Implicit TLS (port 465) — session starts encrypted ──
        elif etype == "IMPLICIT_TLS":
            sec.tls_started = True
            session.mode = "IMPLICIT_TLS"
            self._transition(session, "ENCRYPTED", event)

        # ── Authentication ──
        elif etype == "AUTH_ATTEMPT":
            sec.authentication_attempted = True
            mechanism = event.raw_data.strip() if event.raw_data else None
            if mechanism:
                sec.auth_mechanism = mechanism
            # Detect pre-TLS authentication
            if not sec.tls_started:
                sec.authentication_before_tls = True
            if state in ("CAPABILITY_RESPONSE", "EHLO_HELO", "ENCRYPTED",
                         "TLS_HANDSHAKE", "STARTTLS_REJECTED"):
                self._transition(session, "AUTHENTICATION", event)

        elif etype == "AUTH_SUCCESS":
            if state == "AUTHENTICATION":
                self._transition(session, "AUTH_SUCCESS", event)

        elif etype == "AUTH_FAILED":
            if state == "AUTHENTICATION":
                self._transition(session, "AUTH_FAILED", event)

        # ── Mail transaction commands ──
        elif etype == "MAIL_FROM":
            sec.mail_from = event.raw_data.strip() if event.raw_data else None
            if state in ("AUTH_SUCCESS", "CAPABILITY_RESPONSE", "EHLO_HELO",
                         "ENCRYPTED", "MAIL_TRANSACTION"):
                self._transition(session, "MAIL_TRANSACTION", event)

        elif etype == "RCPT_TO":
            rcpt = event.raw_data.strip() if event.raw_data else None
            if rcpt:
                sec.rcpt_to.append(rcpt)
            # Stay in MAIL_TRANSACTION

        elif etype == "DATA_START":
            sec.data_started = True
            if state == "MAIL_TRANSACTION":
                self._transition(session, "DATA_TRANSFER", event)

        elif etype == "DATA_ACCEPTED":
            if state == "DATA_TRANSFER":
                self._transition(session, "MAIL_TRANSACTION", event)

        # ── Session end ──
        elif etype == "QUIT":
            self._transition(session, "CLOSED", event)

        elif etype == "RSET":
            # RSET returns to the post-EHLO state
            if state in ("MAIL_TRANSACTION", "DATA_TRANSFER",
                         "AUTH_SUCCESS", "AUTH_FAILED"):
                self._transition(session, "CAPABILITY_RESPONSE", event)

        elif etype == "CONNECTION_LOST":
            self._transition(session, "CLOSED", event)

        elif etype == "SERVER_ERROR":
            if state != "CLOSED":
                self._transition(session, "ERROR", event)

        # ── NOOP (no state change, but we log the event) ──
        elif etype == "NOOP":
            pass  # Event is still recorded; no state transition

        # Unknown event types are ignored but logged
        else:
            session.parse_warnings.append(
                f"Unhandled SMTP event: {etype} in state {state}"
            )


# ─── IMAP State Machine ────────────────────────────────────────────

IMAP_STATES = {
    "TCP_CONNECTED",
    "IMAP_GREETING",
    "NON_AUTHENTICATED",
    "CAPABILITY_RECEIVED",
    "STARTTLS_REQUESTED",
    "STARTTLS_ACCEPTED",
    "STARTTLS_REJECTED",
    "TLS_HANDSHAKE",
    "ENCRYPTED",
    "AUTHENTICATION",
    "AUTHENTICATED",
    "SELECTED",
    "LOGOUT",
    "CLOSED",
    "ERROR",
}

IMAP_TERMINAL = {"CLOSED", "ERROR", "ENCRYPTED"}


class IMAPSessionStateMachine(ProtocolStateMachine):
    """
    Event-driven IMAP state machine (RFC 3501 states).

    IMAP states: Non-Authenticated → Authenticated → Selected → Logout
    with optional STARTTLS upgrade before authentication.
    """

    @property
    def valid_states(self) -> set[str]:
        return IMAP_STATES

    @property
    def terminal_states(self) -> set[str]:
        return IMAP_TERMINAL

    def process_event(self, session: EmailSession, event: SessionEvent) -> None:
        etype = event.event_type
        state = session.state
        sec = session.security

        if etype == "IMAP_GREETING":
            if state == "TCP_CONNECTED":
                self._transition(session, "IMAP_GREETING", event)

        elif etype == "CAPABILITY_RESPONSE":
            if state in ("IMAP_GREETING", "TCP_CONNECTED"):
                self._transition(session, "NON_AUTHENTICATED", event)

        elif etype == "STARTTLS_ADVERTISED":
            sec.starttls_advertised = True

        elif etype == "CAPABILITY_ITEM":
            cap = event.raw_data.strip()
            if cap and cap not in sec.advertised_capabilities:
                sec.advertised_capabilities.append(cap)

        elif etype == "STARTTLS_REQUESTED":
            sec.starttls_requested = True
            if state in ("NON_AUTHENTICATED", "IMAP_GREETING"):
                self._transition(session, "STARTTLS_REQUESTED", event)

        elif etype == "STARTTLS_ACCEPTED":
            sec.starttls_accepted = True
            if state == "STARTTLS_REQUESTED":
                self._transition(session, "STARTTLS_ACCEPTED", event)

        elif etype == "STARTTLS_REJECTED":
            sec.starttls_rejected = True
            if state == "STARTTLS_REQUESTED":
                self._transition(session, "STARTTLS_REJECTED", event)

        elif etype == "TLS_HANDSHAKE_STARTED":
            sec.tls_started = True
            session.mode = "TLS"
            if state in ("STARTTLS_ACCEPTED", "TCP_CONNECTED"):
                self._transition(session, "TLS_HANDSHAKE", event)

        elif etype == "ENCRYPTED_TRAFFIC":
            session.mode = "TLS"
            if state == "TLS_HANDSHAKE":
                self._transition(session, "ENCRYPTED", event)

        elif etype == "IMPLICIT_TLS":
            sec.tls_started = True
            session.mode = "IMPLICIT_TLS"
            self._transition(session, "ENCRYPTED", event)

        elif etype == "AUTH_ATTEMPT":
            sec.authentication_attempted = True
            if not sec.tls_started:
                sec.authentication_before_tls = True
            mechanism = event.raw_data.strip() if event.raw_data else None
            if mechanism:
                sec.auth_mechanism = mechanism
            if state in ("NON_AUTHENTICATED", "IMAP_GREETING",
                         "ENCRYPTED", "TLS_HANDSHAKE",
                         "STARTTLS_REJECTED"):
                self._transition(session, "AUTHENTICATION", event)

        elif etype == "AUTH_SUCCESS":
            if state == "AUTHENTICATION":
                self._transition(session, "AUTHENTICATED", event)

        elif etype == "AUTH_FAILED":
            if state == "AUTHENTICATION":
                self._transition(session, "NON_AUTHENTICATED", event)

        elif etype == "SELECT":
            if state == "AUTHENTICATED":
                self._transition(session, "SELECTED", event)

        elif etype == "LOGOUT":
            self._transition(session, "LOGOUT", event)

        elif etype == "QUIT" or etype == "CONNECTION_LOST":
            self._transition(session, "CLOSED", event)

        elif etype == "SERVER_ERROR":
            if state != "CLOSED":
                self._transition(session, "ERROR", event)

        else:
            session.parse_warnings.append(
                f"Unhandled IMAP event: {etype} in state {state}"
            )


# ─── POP3 State Machine ────────────────────────────────────────────

POP3_STATES = {
    "TCP_CONNECTED",
    "POP3_GREETING",
    "AUTHORIZATION",
    "STLS_REQUESTED",
    "STLS_ACCEPTED",
    "STLS_REJECTED",
    "TLS_HANDSHAKE",
    "ENCRYPTED",
    "AUTHENTICATION",
    "TRANSACTION",
    "UPDATE",
    "CLOSED",
    "ERROR",
}

POP3_TERMINAL = {"CLOSED", "ERROR", "ENCRYPTED"}


class POP3SessionStateMachine(ProtocolStateMachine):
    """
    Event-driven POP3 state machine (RFC 1939 / RFC 2595).

    POP3 states: Authorization → Transaction → Update
    with optional STLS upgrade before authentication.
    """

    @property
    def valid_states(self) -> set[str]:
        return POP3_STATES

    @property
    def terminal_states(self) -> set[str]:
        return POP3_TERMINAL

    def process_event(self, session: EmailSession, event: SessionEvent) -> None:
        etype = event.event_type
        state = session.state
        sec = session.security

        if etype == "POP3_GREETING":
            if state == "TCP_CONNECTED":
                self._transition(session, "POP3_GREETING", event)

        elif etype == "CAPABILITY_RESPONSE":
            if state in ("POP3_GREETING", "TCP_CONNECTED"):
                self._transition(session, "AUTHORIZATION", event)

        elif etype == "STARTTLS_ADVERTISED":
            sec.starttls_advertised = True

        elif etype == "CAPABILITY_ITEM":
            cap = event.raw_data.strip()
            if cap and cap not in sec.advertised_capabilities:
                sec.advertised_capabilities.append(cap)

        elif etype == "STLS_REQUESTED":
            sec.starttls_requested = True
            if state in ("AUTHORIZATION", "POP3_GREETING"):
                self._transition(session, "STLS_REQUESTED", event)

        elif etype == "STLS_ACCEPTED":
            sec.starttls_accepted = True
            if state == "STLS_REQUESTED":
                self._transition(session, "STLS_ACCEPTED", event)

        elif etype == "STLS_REJECTED":
            sec.starttls_rejected = True
            if state == "STLS_REQUESTED":
                self._transition(session, "STLS_REJECTED", event)

        elif etype == "TLS_HANDSHAKE_STARTED":
            sec.tls_started = True
            session.mode = "TLS"
            if state in ("STLS_ACCEPTED", "TCP_CONNECTED"):
                self._transition(session, "TLS_HANDSHAKE", event)

        elif etype == "ENCRYPTED_TRAFFIC":
            session.mode = "TLS"
            if state == "TLS_HANDSHAKE":
                self._transition(session, "ENCRYPTED", event)

        elif etype == "IMPLICIT_TLS":
            sec.tls_started = True
            session.mode = "IMPLICIT_TLS"
            self._transition(session, "ENCRYPTED", event)

        elif etype == "AUTH_ATTEMPT":
            sec.authentication_attempted = True
            if not sec.tls_started:
                sec.authentication_before_tls = True
            mechanism = event.raw_data.strip() if event.raw_data else None
            if mechanism:
                sec.auth_mechanism = mechanism
            if state in ("AUTHORIZATION", "POP3_GREETING",
                         "ENCRYPTED", "TLS_HANDSHAKE",
                         "STLS_REJECTED"):
                self._transition(session, "AUTHENTICATION", event)

        elif etype == "AUTH_SUCCESS":
            if state == "AUTHENTICATION":
                self._transition(session, "TRANSACTION", event)

        elif etype == "AUTH_FAILED":
            if state == "AUTHENTICATION":
                self._transition(session, "AUTHORIZATION", event)

        elif etype == "QUIT":
            if state == "TRANSACTION":
                self._transition(session, "UPDATE", event)
            else:
                self._transition(session, "CLOSED", event)

        elif etype == "CONNECTION_LOST":
            self._transition(session, "CLOSED", event)

        elif etype == "SERVER_ERROR":
            if state != "CLOSED":
                self._transition(session, "ERROR", event)

        else:
            session.parse_warnings.append(
                f"Unhandled POP3 event: {etype} in state {state}"
            )


# ─── Factory ────────────────────────────────────────────────────────

def create_state_machine(protocol: str) -> ProtocolStateMachine:
    """Return the correct state machine for a detected protocol."""
    machines = {
        "SMTP": SMTPSessionStateMachine,
        "IMAP": IMAPSessionStateMachine,
        "POP3": POP3SessionStateMachine,
    }
    cls = machines.get(protocol.upper())
    if cls is None:
        raise ValueError(f"No state machine for protocol: {protocol}")
    return cls()
