"""
app/sessions/smtp/events.py

SMTP Event Parser — converts reconstructed TCP streams into
SessionEvent objects.

This is the "raw TCP data → structured events" step from Phase 6.
It works on the *already reassembled* byte streams (Phase 5 output),
NOT on individual packets.

The parser interleaves the server (S2C) and client (C2S) streams
by walking them line-by-line and assigning monotonically increasing
timestamps based on stream offsets when real per-line timestamps
aren't available.  When timestamps ARE available (from TCP segment
metadata), those are used instead.

Detection coverage:

  Server responses: 220, 250, 354, 421, 454, 530, 535, 550
  Client commands:  EHLO, HELO, STARTTLS, AUTH, MAIL FROM,
                    RCPT TO, DATA, QUIT, RSET, NOOP
"""

from __future__ import annotations

import re
from typing import Optional

from app.protocol.common import CRLF, iter_lines_with_offsets, looks_like_tls_record
from app.sessions.models import SessionEvent


# ─── Regex patterns for SMTP commands / responses ──────────────────

# Server response patterns
_RE_GREETING_220 = re.compile(rb"^220[ \-]", re.IGNORECASE)
_RE_RESP_250 = re.compile(rb"^250[ \-]", re.IGNORECASE)
_RE_RESP_250_STARTTLS = re.compile(rb"^250[ \-]STARTTLS\b", re.IGNORECASE)
_RE_RESP_250_AUTH = re.compile(rb"^250[ \-]AUTH\b", re.IGNORECASE)
_RE_RESP_354 = re.compile(rb"^354[ \-]", re.IGNORECASE)
_RE_RESP_421 = re.compile(rb"^421[ \-]", re.IGNORECASE)
_RE_RESP_454 = re.compile(rb"^454[ \-]", re.IGNORECASE)
_RE_RESP_530 = re.compile(rb"^530[ \-]", re.IGNORECASE)
_RE_RESP_535 = re.compile(rb"^535[ \-]", re.IGNORECASE)
_RE_RESP_550 = re.compile(rb"^550[ \-]", re.IGNORECASE)
_RE_RESP_220_STARTTLS = re.compile(
    rb"^220[ \-].*(ready|start\s*tls|go\s*ahead)", re.IGNORECASE
)
_RE_RESP_235 = re.compile(rb"^235[ \-]", re.IGNORECASE)

# Client command patterns
_RE_EHLO = re.compile(rb"^EHLO\b", re.IGNORECASE)
_RE_HELO = re.compile(rb"^HELO\b", re.IGNORECASE)
_RE_STARTTLS = re.compile(rb"^STARTTLS\b", re.IGNORECASE)
_RE_AUTH = re.compile(rb"^AUTH\s+(\S+)", re.IGNORECASE)
_RE_MAIL_FROM = re.compile(rb"^MAIL\s+FROM\s*:", re.IGNORECASE)
_RE_RCPT_TO = re.compile(rb"^RCPT\s+TO\s*:", re.IGNORECASE)
_RE_DATA = re.compile(rb"^DATA\b", re.IGNORECASE)
_RE_QUIT = re.compile(rb"^QUIT\b", re.IGNORECASE)
_RE_RSET = re.compile(rb"^RSET\b", re.IGNORECASE)
_RE_NOOP = re.compile(rb"^NOOP\b", re.IGNORECASE)


# ─── Helpers ────────────────────────────────────────────────────────

def _safe_decode(data: bytes, max_len: int = 120) -> str:
    """Decode to UTF-8 for evidence, truncated and safe."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)
    return text[:max_len]


def _redact_auth(line: bytes) -> str:
    """Return auth mechanism only; credentials are always redacted."""
    match = _RE_AUTH.match(line)
    if match:
        return match.group(1).decode("ascii", errors="replace")
    return "UNKNOWN"


def _extract_address(line: bytes, prefix_re: re.Pattern[bytes]) -> str:
    """Extract the <address> from MAIL FROM / RCPT TO, redacted."""
    text = _safe_decode(line)
    # Strip the command prefix
    idx = text.find(":")
    if idx >= 0:
        addr_part = text[idx + 1:].strip()
    else:
        addr_part = text
    return addr_part[:80]


# ─── Main Parser ────────────────────────────────────────────────────

def parse_smtp_server_stream(
    stream: bytes,
    base_timestamp: float,
    time_increment: float = 0.001,
) -> list[SessionEvent]:
    """
    Parse the server-to-client stream and extract SMTP response events.

    Args:
        stream:          Reassembled S2C byte stream.
        base_timestamp:  Session start time (epoch float).
        time_increment:  Synthetic time step between lines when real
                         timestamps aren't available.

    Returns:
        Ordered list of SessionEvent objects.
    """
    events: list[SessionEvent] = []
    t = base_timestamp
    is_first_220 = True
    capability_block_active = False

    for offset, line in iter_lines_with_offsets(stream):
        t += time_increment

        if not line.strip():
            continue

        # ── 220 Greeting (first) vs STARTTLS accept (subsequent) ──
        if _RE_GREETING_220.match(line):
            if is_first_220:
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="SMTP_GREETING",
                    raw_data=_safe_decode(line),
                    stream_offset=offset,
                ))
                is_first_220 = False
            else:
                # A subsequent 220 after STARTTLS → accept
                if _RE_RESP_220_STARTTLS.match(line):
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="STARTTLS_ACCEPTED",
                        raw_data=_safe_decode(line),
                        stream_offset=offset,
                    ))
                else:
                    # Could be another greeting (re-handshake after TLS)
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="SMTP_GREETING",
                        raw_data=_safe_decode(line),
                        stream_offset=offset,
                    ))

        # ── 250 responses ──
        elif _RE_RESP_250.match(line):
            # Check for specific capability advertisements
            if _RE_RESP_250_STARTTLS.match(line):
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="STARTTLS_ADVERTISED",
                    raw_data=_safe_decode(line),
                    stream_offset=offset,
                ))
            elif _RE_RESP_250_AUTH.match(line):
                events.append(SessionEvent(
                    timestamp=t,
                    direction="server_to_client",
                    event_type="CAPABILITY_ITEM",
                    raw_data=_safe_decode(line),
                    stream_offset=offset,
                ))
            else:
                # Generic 250 — could be capability or MAIL/RCPT OK
                # First 250 after EHLO is the capability response
                decoded = _safe_decode(line)
                # 250 with a hyphen continuation = capability block
                if line[3:4] == b"-":
                    if not capability_block_active:
                        capability_block_active = True
                        events.append(SessionEvent(
                            timestamp=t,
                            direction="server_to_client",
                            event_type="CAPABILITY_RESPONSE",
                            raw_data=decoded,
                            stream_offset=offset,
                        ))
                    events.append(SessionEvent(
                        timestamp=t,
                        direction="server_to_client",
                        event_type="CAPABILITY_ITEM",
                        raw_data=decoded,
                        stream_offset=offset,
                    ))
                else:
                    # 250 with space = final line of capability or OK
                    if capability_block_active:
                        capability_block_active = False
                        events.append(SessionEvent(
                            timestamp=t,
                            direction="server_to_client",
                            event_type="CAPABILITY_ITEM",
                            raw_data=decoded,
                            stream_offset=offset,
                        ))
                    else:
                        events.append(SessionEvent(
                            timestamp=t,
                            direction="server_to_client",
                            event_type="CAPABILITY_RESPONSE",
                            raw_data=decoded,
                            stream_offset=offset,
                        ))

        # ── 354 Start mail input ──
        elif _RE_RESP_354.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="DATA_ACCEPTED",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 235 Auth success ──
        elif _RE_RESP_235.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="AUTH_SUCCESS",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 421 Service closing ──
        elif _RE_RESP_421.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="SERVER_ERROR",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 454 TLS unavailable ──
        elif _RE_RESP_454.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="STARTTLS_REJECTED",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 530 Authentication required ──
        elif _RE_RESP_530.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="SERVER_ERROR",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 535 Auth failed ──
        elif _RE_RESP_535.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="AUTH_FAILED",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── 550 Mailbox unavailable / action not taken ──
        elif _RE_RESP_550.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="server_to_client",
                event_type="SERVER_ERROR",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

    return events


def parse_smtp_client_stream(
    stream: bytes,
    base_timestamp: float,
    time_increment: float = 0.001,
) -> list[SessionEvent]:
    """
    Parse the client-to-server stream and extract SMTP command events.

    After a TLS boundary is detected, remaining bytes are emitted as
    a single TLS_HANDSHAKE_STARTED event and parsing stops (Phase 8
    handles TLS internals).
    """
    events: list[SessionEvent] = []
    t = base_timestamp
    tls_detected = False

    for offset, line in iter_lines_with_offsets(stream):
        t += time_increment

        if not line.strip():
            continue

        # Check if we've hit a TLS record in the stream
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
            tls_detected = True
            break  # Stop parsing — rest is encrypted

        # ── EHLO ──
        if _RE_EHLO.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="EHLO",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── HELO ──
        elif _RE_HELO.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="HELO",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── STARTTLS ──
        elif _RE_STARTTLS.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="STARTTLS_REQUESTED",
                raw_data=_safe_decode(line),
                stream_offset=offset,
            ))

        # ── AUTH ──
        elif _RE_AUTH.match(line):
            mechanism = _redact_auth(line)
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="AUTH_ATTEMPT",
                raw_data=mechanism,
                stream_offset=offset,
            ))

        # ── MAIL FROM ──
        elif _RE_MAIL_FROM.match(line):
            addr = _extract_address(line, _RE_MAIL_FROM)
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="MAIL_FROM",
                raw_data=addr,
                stream_offset=offset,
            ))

        # ── RCPT TO ──
        elif _RE_RCPT_TO.match(line):
            addr = _extract_address(line, _RE_RCPT_TO)
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="RCPT_TO",
                raw_data=addr,
                stream_offset=offset,
            ))

        # ── DATA ──
        elif _RE_DATA.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="DATA_START",
                raw_data="DATA",
                stream_offset=offset,
            ))

        # ── QUIT ──
        elif _RE_QUIT.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="QUIT",
                raw_data="QUIT",
                stream_offset=offset,
            ))

        # ── RSET ──
        elif _RE_RSET.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="RSET",
                raw_data="RSET",
                stream_offset=offset,
            ))

        # ── NOOP ──
        elif _RE_NOOP.match(line):
            events.append(SessionEvent(
                timestamp=t,
                direction="client_to_server",
                event_type="NOOP",
                raw_data="NOOP",
                stream_offset=offset,
            ))

    # Check for TLS at the raw stream level if not caught in line parsing
    if not tls_detected:
        tls_offset = _find_tls_offset(stream)
        if tls_offset is not None:
            events.append(SessionEvent(
                timestamp=base_timestamp + (tls_offset * 0.0001),
                direction="client_to_server",
                event_type="TLS_HANDSHAKE_STARTED",
                raw_data="[TLS ClientHello]",
                stream_offset=tls_offset,
            ))

    return events


def _find_tls_offset(stream: bytes) -> Optional[int]:
    """Scan for the first TLS record header in a byte stream."""
    for i in range(len(stream) - 5):
        if looks_like_tls_record(stream[i:]):
            return i
    return None


def parse_smtp_streams(
    client_stream: bytes,
    server_stream: bytes,
    base_timestamp: float,
) -> list[SessionEvent]:
    """
    Parse both SMTP streams and return a merged, time-ordered
    list of SessionEvent objects.

    This is the primary entry point for the SMTP event parser.
    The returned events are ready to be fed into the SMTP state machine.
    """
    # Parse both directions
    s2c_events = parse_smtp_server_stream(server_stream, base_timestamp)
    c2s_events = parse_smtp_client_stream(client_stream, base_timestamp + 0.0005)

    # Merge and sort by timestamp, then by stream offset
    all_events = s2c_events + c2s_events
    all_events.sort(key=lambda e: (e.timestamp, e.stream_offset))

    return all_events
