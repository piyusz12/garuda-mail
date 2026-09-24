"""
app/sessions/imap/events.py

IMAP Event Parser — converts reconstructed TCP streams into
SessionEvent objects for the IMAP state machine.

IMAP commands are tagged (e.g. "A001 STARTTLS"), and server responses
are prefixed with "*" (untagged) or a tag (tagged completion).
This parser handles both forms.

Detection coverage:

  Server:  * OK, * CAPABILITY, tagged OK/NO/BAD, * BYE
  Client:  CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE, SELECT,
           EXAMINE, LOGOUT, NOOP
"""

from __future__ import annotations

import re
from typing import Optional

from app.protocol.common import iter_lines_with_offsets, looks_like_tls_record
from app.sessions.models import SessionEvent


# ─── Patterns ──────────────────────────────────────────────────────

_RE_UNTAGGED_OK = re.compile(rb"^\*\s+OK\b", re.IGNORECASE)
_RE_UNTAGGED_BYE = re.compile(rb"^\*\s+BYE\b", re.IGNORECASE)
_RE_UNTAGGED_CAPABILITY = re.compile(rb"^\*\s+CAPABILITY\b", re.IGNORECASE)
_RE_TAGGED_RESPONSE = re.compile(
    rb"^([A-Za-z0-9]+)\s+(OK|NO|BAD)\b", re.IGNORECASE
)

_RE_CMD_CAPABILITY = re.compile(
    rb"^([A-Za-z0-9]+)\s+CAPABILITY\b", re.IGNORECASE
)
_RE_CMD_STARTTLS = re.compile(
    rb"^([A-Za-z0-9]+)\s+STARTTLS\b", re.IGNORECASE
)
_RE_CMD_LOGIN = re.compile(
    rb"^([A-Za-z0-9]+)\s+LOGIN\b", re.IGNORECASE
)
_RE_CMD_AUTHENTICATE = re.compile(
    rb"^([A-Za-z0-9]+)\s+AUTHENTICATE\s+(\S+)", re.IGNORECASE
)
_RE_CMD_SELECT = re.compile(
    rb"^([A-Za-z0-9]+)\s+SELECT\b", re.IGNORECASE
)
_RE_CMD_EXAMINE = re.compile(
    rb"^([A-Za-z0-9]+)\s+EXAMINE\b", re.IGNORECASE
)
_RE_CMD_LOGOUT = re.compile(
    rb"^([A-Za-z0-9]+)\s+LOGOUT\b", re.IGNORECASE
)
_RE_CMD_NOOP = re.compile(
    rb"^([A-Za-z0-9]+)\s+NOOP\b", re.IGNORECASE
)


def _safe_decode(data: bytes, max_len: int = 120) -> str:
    try:
        return data.decode("utf-8", errors="replace")[:max_len]
    except Exception:
        return repr(data)[:max_len]


# ─── Server stream parser ──────────────────────────────────────────

def parse_imap_server_stream(
    stream: bytes,
    base_timestamp: float,
    time_increment: float = 0.001,
) -> list[SessionEvent]:
    events: list[SessionEvent] = []
    t = base_timestamp
    greeting_seen = False
    # Track pending tags to match completion responses to commands
    pending_starttls_tag: Optional[str] = None
    pending_auth_tag: Optional[str] = None

    for offset, line in iter_lines_with_offsets(stream):
        t += time_increment
        if not line.strip():
            continue

        # ── * OK greeting (first untagged OK) ──
        if _RE_UNTAGGED_OK.match(line) and not greeting_seen:
            greeting_seen = True
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="IMAP_GREETING",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── * CAPABILITY ──
        elif _RE_UNTAGGED_CAPABILITY.match(line):
            decoded = _safe_decode(line)
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="CAPABILITY_RESPONSE",
                raw_data=decoded,
                stream_offset=offset,
            ))
            # Check for STARTTLS in capabilities
            if b"STARTTLS" in line.upper():
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="STARTTLS_ADVERTISED",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
            # Extract individual capabilities
            parts = line.split()
            for part in parts[2:]:  # Skip "* CAPABILITY"
                cap = part.decode("ascii", errors="replace")
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="CAPABILITY_ITEM",
                    raw_data=cap,
                    stream_offset=offset,
                ))

        # ── * BYE ──
        elif _RE_UNTAGGED_BYE.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="CONNECTION_LOST",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── Tagged response (OK / NO / BAD) ──
        elif (m := _RE_TAGGED_RESPONSE.match(line)):
            tag = m.group(1).decode("ascii", errors="replace").upper()
            result = m.group(2).decode("ascii", errors="replace").upper()
            decoded = _safe_decode(line)

            if result == "OK":
                # Check if this completes a STARTTLS command
                if b"TLS" in line.upper() or b"BEGIN" in line.upper():
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="STARTTLS_ACCEPTED",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))
                elif b"LOGIN" in line.upper() or b"AUTH" in line.upper():
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="AUTH_SUCCESS",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))
                # Generic OK — no special handling
            elif result == "NO" or result == "BAD":
                if b"TLS" in line.upper():
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="STARTTLS_REJECTED",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))
                elif b"LOGIN" in line.upper() or b"AUTH" in line.upper():
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="AUTH_FAILED",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))
                else:
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="SERVER_ERROR",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))

    return events


# ─── Client stream parser ──────────────────────────────────────────

def parse_imap_client_stream(
    stream: bytes,
    base_timestamp: float,
    time_increment: float = 0.001,
) -> list[SessionEvent]:
    events: list[SessionEvent] = []
    t = base_timestamp

    for offset, line in iter_lines_with_offsets(stream):
        t += time_increment
        if not line.strip():
            continue

        # TLS boundary detection
        if looks_like_tls_record(line) or (
            len(line) > 5 and line[0] == 0x16 and line[1] == 0x03
        ):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="TLS_HANDSHAKE_STARTED",
                raw_data="[TLS ClientHello]",
                stream_offset=offset,
            ))
            break

        if _RE_CMD_STARTTLS.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="STARTTLS_REQUESTED",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        elif _RE_CMD_LOGIN.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data="LOGIN",
                stream_offset=offset,
            ))

        elif (m := _RE_CMD_AUTHENTICATE.match(line)):
            mech = m.group(2).decode("ascii", errors="replace")
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data=mech,
                stream_offset=offset,
            ))

        elif _RE_CMD_SELECT.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="SELECT",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        elif _RE_CMD_EXAMINE.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="SELECT",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        elif _RE_CMD_LOGOUT.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="LOGOUT",
                raw_data="LOGOUT",
                stream_offset=offset,
            ))

        elif _RE_CMD_CAPABILITY.match(line):
            pass  # Client asking for capabilities; response is what matters

        elif _RE_CMD_NOOP.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="NOOP",
                raw_data="NOOP",
                stream_offset=offset,
            ))

    # TLS boundary scan at raw level
    tls_offset = _find_tls_offset(stream)
    if tls_offset is not None and not any(
        e.event_type == "TLS_HANDSHAKE_STARTED" for e in events
    ):
        events.append(SessionEvent(
            timestamp=base_timestamp + (tls_offset * 0.0001),
            direction="client_to_server",
            event_type="TLS_HANDSHAKE_STARTED",
            raw_data="[TLS ClientHello]",
            stream_offset=tls_offset,
        ))

    return events


def _find_tls_offset(stream: bytes) -> Optional[int]:
    for i in range(len(stream) - 5):
        if looks_like_tls_record(stream[i:]):
            return i
    return None


def parse_imap_streams(
    client_stream: bytes,
    server_stream: bytes,
    base_timestamp: float,
) -> list[SessionEvent]:
    """Main entry point: parse both IMAP streams and merge events."""
    s2c_events = parse_imap_server_stream(server_stream, base_timestamp)
    c2s_events = parse_imap_client_stream(client_stream, base_timestamp + 0.0005)
    all_events = s2c_events + c2s_events
    all_events.sort(key=lambda e: (e.timestamp, e.stream_offset))
    return all_events
