"""
app/sessions/pop3/events.py

POP3 Event Parser — converts reconstructed TCP streams into
SessionEvent objects for the POP3 state machine.

POP3 is simpler than SMTP/IMAP: server responses are "+OK" or "-ERR",
and client commands are untagged single-word verbs.

Detection coverage:

  Server:  +OK (greeting, STLS accept, PASS accept), -ERR,
           CAPA responses including STLS capability
  Client:  CAPA, STLS, USER, PASS, STAT, LIST, RETR, DELE,
           QUIT, NOOP
"""

from __future__ import annotations

import re
from typing import Optional

from app.protocol.common import iter_lines_with_offsets, looks_like_tls_record
from app.sessions.models import SessionEvent


# ─── Patterns ──────────────────────────────────────────────────────

_RE_OK = re.compile(rb"^\+OK\b", re.IGNORECASE)
_RE_ERR = re.compile(rb"^-ERR\b", re.IGNORECASE)

_RE_CMD_CAPA = re.compile(rb"^CAPA\b", re.IGNORECASE)
_RE_CMD_STLS = re.compile(rb"^STLS\b", re.IGNORECASE)
_RE_CMD_USER = re.compile(rb"^USER\s+", re.IGNORECASE)
_RE_CMD_PASS = re.compile(rb"^PASS\s+", re.IGNORECASE)
_RE_CMD_QUIT = re.compile(rb"^QUIT\b", re.IGNORECASE)
_RE_CMD_STAT = re.compile(rb"^STAT\b", re.IGNORECASE)
_RE_CMD_LIST = re.compile(rb"^LIST\b", re.IGNORECASE)
_RE_CMD_RETR = re.compile(rb"^RETR\b", re.IGNORECASE)
_RE_CMD_DELE = re.compile(rb"^DELE\b", re.IGNORECASE)
_RE_CMD_NOOP = re.compile(rb"^NOOP\b", re.IGNORECASE)
_RE_CMD_AUTH = re.compile(rb"^AUTH\s+(\S+)", re.IGNORECASE)


def _safe_decode(data: bytes, max_len: int = 120) -> str:
    try:
        return data.decode("utf-8", errors="replace")[:max_len]
    except Exception:
        return repr(data)[:max_len]


# ─── Server stream parser ──────────────────────────────────────────

def parse_pop3_server_stream(
    stream: bytes,
    base_timestamp: float,
    time_increment: float = 0.001,
) -> list[SessionEvent]:
    events: list[SessionEvent] = []
    t = base_timestamp
    greeting_seen = False
    in_capa_response = False
    last_client_cmd: Optional[str] = None  # For context-aware OK matching

    for offset, line in iter_lines_with_offsets(stream):
        t += time_increment
        if not line.strip():
            continue

        decoded = _safe_decode(line)

        # ── CAPA multi-line response body (lines between +OK and ".") ──
        if in_capa_response:
            if line.strip() == b".":
                in_capa_response = False
                continue
            cap = decoded.strip()
            if cap.upper() == "STLS":
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="STARTTLS_ADVERTISED",
                    raw_data=cap,
                    stream_offset=offset,
                ))
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="CAPABILITY_ITEM",
                raw_data=cap,
                stream_offset=offset,
            ))
            continue

        # ── +OK ──
        if _RE_OK.match(line):
            if not greeting_seen:
                greeting_seen = True
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="POP3_GREETING",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
            elif b"TLS" in line.upper() or b"BEGIN" in line.upper():
                # STLS accepted
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="STLS_ACCEPTED",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
            elif b"CAPA" in line.upper() or b"CAPABILITY" in line.upper():
                # Start of CAPA multi-line response
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="CAPABILITY_RESPONSE",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
                in_capa_response = True
            elif b"LOGGED" in line.upper() or b"MAILDROP" in line.upper() or b"WELCOME" in line.upper():
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="AUTH_SUCCESS",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
            else:
                # Generic +OK — could be response to PASS, USER, etc.
                # We'll emit a generic OK; the state machine uses context
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="AUTH_SUCCESS",
                    raw_data=decoded,
                    stream_offset=offset,
                ))

        # ── -ERR ──
        elif _RE_ERR.match(line):
            if b"TLS" in line.upper() or b"STLS" in line.upper():
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="STLS_REJECTED",
                    raw_data=decoded,
                    stream_offset=offset,
                ))
            elif b"AUTH" in line.upper() or b"LOGIN" in line.upper() or b"PASS" in line.upper():
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

def parse_pop3_client_stream(
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

        # TLS boundary
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

        if _RE_CMD_STLS.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="STLS_REQUESTED",
                raw_data="STLS",
                stream_offset=offset,
            ))

        elif _RE_CMD_USER.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data="USER",
                stream_offset=offset,
            ))

        elif _RE_CMD_PASS.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data="PASS [REDACTED]",
                stream_offset=offset,
            ))

        elif (m := _RE_CMD_AUTH.match(line)):
            mech = m.group(1).decode("ascii", errors="replace")
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data=mech,
                stream_offset=offset,
            ))

        elif _RE_CMD_QUIT.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="QUIT",
                raw_data="QUIT",
                stream_offset=offset,
            ))

        elif _RE_CMD_CAPA.match(line):
            pass  # Request for capabilities; response matters

        elif _RE_CMD_NOOP.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="NOOP",
                raw_data="NOOP",
                stream_offset=offset,
            ))

    # TLS boundary fallback scan
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


def parse_pop3_streams(
    client_stream: bytes,
    server_stream: bytes,
    base_timestamp: float,
) -> list[SessionEvent]:
    """Main entry point: parse both POP3 streams and merge events."""
    s2c_events = parse_pop3_server_stream(server_stream, base_timestamp)
    c2s_events = parse_pop3_client_stream(client_stream, base_timestamp + 0.0005)
    all_events = s2c_events + c2s_events
    all_events.sort(key=lambda e: (e.timestamp, e.stream_offset))
    return all_events
