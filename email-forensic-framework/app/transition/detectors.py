"""
app/transition/detectors.py

Individual detection functions for Phase 7.

Each function examines one aspect of the TLS transition and populates
the TLSUpgradeResult accordingly.  The analyzer.py orchestrator calls
them in sequence.

Design principle: each detector is pure-ish — it reads from the
EmailSession and writes to the TLSUpgradeResult.  No detector depends
on the output of another, so they can be reordered or skipped.

Detection functions:
  detect_implicit_tls       — TLS from first byte (port 465/993/995)
  detect_capability         — STARTTLS / STLS advertised in capabilities
  detect_starttls_request   — client sent STARTTLS / STLS command
  detect_acceptance         — server responded with success code
  detect_rejection          — server responded with failure code
  detect_tls_handshake      — TLS ClientHello observed in stream
  detect_authentication     — auth timing relative to TLS transition
  detect_plaintext_after_tls — plaintext traffic after TLS accepted
"""

from __future__ import annotations

from typing import Optional

from app.sessions.models import EmailSession, SessionEvent
from app.transition.models import (
    TLSUpgradeResult,
    TransitionEvidence,
    AuthenticationTiming,
)
from app.transition.rules import (
    TLSMode,
    IMPLICIT_TLS_PORTS,
    TLS_ADVERTISE_EVENTS,
    TLS_REQUEST_EVENTS,
    TLS_ACCEPT_EVENTS,
    TLS_REJECT_EVENTS,
    AUTH_EVENTS,
    CONFIDENCE_WEIGHTS,
)


# ─── Helpers ────────────────────────────────────────────────────────

def _find_first_event(
    session: EmailSession, event_types: set[str]
) -> Optional[SessionEvent]:
    """Return the first event matching any of the given types."""
    for ev in session.events:
        if ev.event_type in event_types:
            return ev
    return None


def _find_all_events(
    session: EmailSession, event_types: set[str]
) -> list[SessionEvent]:
    """Return all events matching any of the given types."""
    return [ev for ev in session.events if ev.event_type in event_types]


def _has_event(session: EmailSession, event_types: set[str]) -> bool:
    """Check if any event of the given types exists."""
    return any(ev.event_type in event_types for ev in session.events)


# ─── Detector: Implicit TLS ────────────────────────────────────────

def detect_implicit_tls(
    session: EmailSession, result: TLSUpgradeResult
) -> bool:
    """
    Detect if the connection started with TLS immediately (no STARTTLS).

    Returns True if implicit TLS was detected, False otherwise.
    When True, the caller should skip STARTTLS-specific detectors.
    """
    # Check session mode (set by Phase 6's SessionManager)
    if session.mode == "IMPLICIT_TLS":
        result.tls_mode = TLSMode.IMPLICIT_TLS
        result.tls_handshake_observed = True
        result.capability_advertised = None   # Not applicable
        result.tls_requested = None           # Not applicable
        result.tls_accepted = None            # Not applicable
        result.confidence += CONFIDENCE_WEIGHTS["implicit_tls"]

        # Find the implicit TLS event for evidence
        implicit_ev = _find_first_event(session, {"IMPLICIT_TLS"})
        if implicit_ev:
            result.add_evidence(TransitionEvidence(
                event_type="IMPLICIT_TLS",
                timestamp=implicit_ev.timestamp,
                stream_offset=implicit_ev.stream_offset,
                direction=implicit_ev.direction,
                raw_data=implicit_ev.raw_data,
                description="Connection started directly with TLS",
            ))

        # Check if we also know the port
        if session.server_port in IMPLICIT_TLS_PORTS:
            result.add_evidence(TransitionEvidence(
                event_type="IMPLICIT_TLS_PORT",
                description=(
                    f"Server port {session.server_port} is a known "
                    f"implicit TLS port (RFC 8314)"
                ),
            ))
            result.confidence += 0.10

        return True

    # Fallback: check if the first event is a TLS handshake
    # (session might not have been tagged as IMPLICIT_TLS but the
    #  first client event is a TLS ClientHello)
    if session.events:
        first_client = None
        for ev in session.events:
            if ev.direction == "client_to_server":
                first_client = ev
                break
        if first_client and first_client.event_type == "TLS_HANDSHAKE_STARTED":
            # No protocol greeting before TLS → likely implicit TLS
            has_greeting = any(
                ev.event_type in (
                    "SMTP_GREETING", "IMAP_GREETING", "POP3_GREETING"
                )
                for ev in session.events
                if ev.timestamp <= first_client.timestamp
            )
            if not has_greeting:
                result.tls_mode = TLSMode.IMPLICIT_TLS
                result.tls_handshake_observed = True
                result.capability_advertised = None
                result.tls_requested = None
                result.tls_accepted = None
                result.confidence += CONFIDENCE_WEIGHTS["implicit_tls"]
                result.add_evidence(TransitionEvidence(
                    event_type="TLS_HANDSHAKE_STARTED",
                    timestamp=first_client.timestamp,
                    stream_offset=first_client.stream_offset,
                    direction=first_client.direction,
                    description="TLS handshake before any protocol greeting",
                ))
                return True

    return False


# ─── Detector: Capability Advertisement ────────────────────────────

def detect_capability(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """Detect whether STARTTLS / STLS was advertised in server capabilities."""
    proto = session.protocol.upper()
    advertise_events = TLS_ADVERTISE_EVENTS.get(proto, set())

    if session.security.starttls_advertised or _has_event(session, advertise_events):
        result.capability_advertised = True
        result.confidence += CONFIDENCE_WEIGHTS["capability_advertised"]

        ev = _find_first_event(session, advertise_events)
        if ev:
            result.add_evidence(TransitionEvidence(
                event_type=ev.event_type,
                timestamp=ev.timestamp,
                stream_offset=ev.stream_offset,
                direction=ev.direction,
                raw_data=ev.raw_data,
                description=f"Server advertised {ev.event_type} capability",
            ))
    else:
        result.capability_advertised = False


# ─── Detector: STARTTLS Request ────────────────────────────────────

def detect_starttls_request(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """Detect whether the client sent a STARTTLS / STLS command."""
    proto = session.protocol.upper()
    request_events = TLS_REQUEST_EVENTS.get(proto, set())

    if session.security.starttls_requested or _has_event(session, request_events):
        result.tls_requested = True
        result.confidence += CONFIDENCE_WEIGHTS["tls_requested"]

        ev = _find_first_event(session, request_events)
        if ev:
            result.add_evidence(TransitionEvidence(
                event_type=ev.event_type,
                timestamp=ev.timestamp,
                stream_offset=ev.stream_offset,
                direction=ev.direction,
                raw_data=ev.raw_data,
                description="Client requested TLS upgrade",
            ))
    else:
        result.tls_requested = False


# ─── Detector: Server Acceptance ───────────────────────────────────

def detect_acceptance(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """Detect whether the server accepted the STARTTLS / STLS request."""
    proto = session.protocol.upper()
    accept_events = TLS_ACCEPT_EVENTS.get(proto, set())

    if session.security.starttls_accepted or _has_event(session, accept_events):
        result.tls_accepted = True
        result.confidence += CONFIDENCE_WEIGHTS["tls_accepted"]

        ev = _find_first_event(session, accept_events)
        if ev:
            result.add_evidence(TransitionEvidence(
                event_type=ev.event_type,
                timestamp=ev.timestamp,
                stream_offset=ev.stream_offset,
                direction=ev.direction,
                raw_data=ev.raw_data,
                description="Server accepted TLS upgrade",
            ))
    else:
        result.tls_accepted = False


# ─── Detector: Server Rejection ────────────────────────────────────

def detect_rejection(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """Detect whether the server rejected the STARTTLS / STLS request."""
    proto = session.protocol.upper()
    reject_events = TLS_REJECT_EVENTS.get(proto, set())

    if session.security.starttls_rejected or _has_event(session, reject_events):
        result.tls_accepted = False
        result.confidence += CONFIDENCE_WEIGHTS["tls_rejected"]

        ev = _find_first_event(session, reject_events)
        if ev:
            result.add_evidence(TransitionEvidence(
                event_type=ev.event_type,
                timestamp=ev.timestamp,
                stream_offset=ev.stream_offset,
                direction=ev.direction,
                raw_data=ev.raw_data,
                description="Server rejected TLS upgrade",
            ))


# ─── Detector: TLS Handshake ──────────────────────────────────────

def detect_tls_handshake(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """Detect whether a TLS handshake (ClientHello) was observed."""
    tls_events = {"TLS_HANDSHAKE_STARTED", "ENCRYPTED_TRAFFIC"}

    if session.security.tls_started or _has_event(session, tls_events):
        result.tls_handshake_observed = True
        result.confidence += CONFIDENCE_WEIGHTS["tls_handshake_observed"]

        ev = _find_first_event(session, tls_events)
        if ev:
            result.add_evidence(TransitionEvidence(
                event_type=ev.event_type,
                timestamp=ev.timestamp,
                stream_offset=ev.stream_offset,
                direction=ev.direction,
                raw_data=ev.raw_data,
                description="TLS handshake observed in stream",
            ))
    else:
        result.tls_handshake_observed = False


# ─── Detector: Authentication Timing ──────────────────────────────

def detect_authentication(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """
    Determine whether authentication happened before or after TLS.

    Uses event timestamps from Phase 6 for forensic precision.
    Records the delta in milliseconds between auth and TLS events.
    """
    proto = session.protocol.upper()
    auth_event_types = AUTH_EVENTS.get(proto, set())
    tls_event_types = {"TLS_HANDSHAKE_STARTED", "ENCRYPTED_TRAFFIC", "IMPLICIT_TLS"}

    auth_events = _find_all_events(session, auth_event_types)
    tls_ev = _find_first_event(session, tls_event_types)

    if not auth_events:
        # No authentication observed — nothing to report
        return

    timing = AuthenticationTiming()
    first_auth = auth_events[0]
    timing.auth_timestamp = first_auth.timestamp
    timing.auth_mechanism = session.security.auth_mechanism

    if tls_ev:
        timing.tls_timestamp = tls_ev.timestamp
        delta_s = first_auth.timestamp - tls_ev.timestamp
        timing.delta_ms = delta_s * 1000

        if first_auth.timestamp < tls_ev.timestamp:
            timing.before_tls = True
            result.add_evidence(TransitionEvidence(
                event_type="AUTH_BEFORE_TLS",
                timestamp=first_auth.timestamp,
                stream_offset=first_auth.stream_offset,
                direction=first_auth.direction,
                description=(
                    f"Authentication ({timing.auth_mechanism or 'unknown'}) "
                    f"occurred {abs(timing.delta_ms):.1f} ms before TLS"
                ),
            ))
        else:
            timing.after_tls = True
            result.add_evidence(TransitionEvidence(
                event_type="AUTH_AFTER_TLS",
                timestamp=first_auth.timestamp,
                stream_offset=first_auth.stream_offset,
                direction=first_auth.direction,
                description=(
                    f"Authentication ({timing.auth_mechanism or 'unknown'}) "
                    f"occurred {timing.delta_ms:.1f} ms after TLS"
                ),
            ))
    else:
        # Auth happened but no TLS at all → definitely before TLS
        if session.security.authentication_before_tls:
            timing.before_tls = True
            result.add_evidence(TransitionEvidence(
                event_type="AUTH_BEFORE_TLS",
                timestamp=first_auth.timestamp,
                stream_offset=first_auth.stream_offset,
                direction=first_auth.direction,
                description=(
                    f"Authentication ({timing.auth_mechanism or 'unknown'}) "
                    f"with no TLS observed in session"
                ),
            ))
        elif session.security.authentication_attempted:
            # Auth happened, no TLS → before TLS by definition
            timing.before_tls = True
            result.add_evidence(TransitionEvidence(
                event_type="AUTH_BEFORE_TLS",
                timestamp=first_auth.timestamp,
                description="Authentication without any TLS in session",
            ))

    result.authentication = timing
    result.confidence += CONFIDENCE_WEIGHTS["auth_timing_determined"]


# ─── Detector: Plaintext After TLS ─────────────────────────────────

def detect_plaintext_after_tls(
    session: EmailSession, result: TLSUpgradeResult
) -> None:
    """
    Detect if recognizable plaintext appeared after TLS was accepted.

    This is a serious anomaly — after TLS, SMTP/IMAP/POP3 commands
    should be inside encrypted TLS application data and NOT visible
    in a passive capture.

    Caveats:
    - After TLS, the reassembled stream may contain binary TLS data
      that *happens* to start with ASCII bytes.  We only flag if we
      see actual protocol commands (EHLO, LOGIN, etc.).
    """
    tls_ev = _find_first_event(
        session, {"TLS_HANDSHAKE_STARTED", "STARTTLS_ACCEPTED", "STLS_ACCEPTED"}
    )
    if not tls_ev:
        return

    # Plaintext protocol commands that should NOT appear after TLS
    plaintext_indicators = {
        "EHLO", "HELO", "MAIL_FROM", "RCPT_TO", "DATA_START",
        "AUTH_ATTEMPT", "QUIT", "SELECT", "LOGOUT",
    }

    for ev in session.events:
        if ev.timestamp > tls_ev.timestamp and ev.event_type in plaintext_indicators:
            if ev.direction == "client_to_server":
                result.plaintext_after_tls = True
                result.add_evidence(TransitionEvidence(
                    event_type="PLAINTEXT_AFTER_TLS",
                    timestamp=ev.timestamp,
                    stream_offset=ev.stream_offset,
                    direction=ev.direction,
                    raw_data=ev.raw_data,
                    description=(
                        f"Plaintext command '{ev.event_type}' observed "
                        f"after TLS transition"
                    ),
                ))
                result.warnings.append(
                    f"Plaintext {ev.event_type} after TLS at offset "
                    f"{ev.stream_offset}"
                )
                break  # One is enough to flag the anomaly
