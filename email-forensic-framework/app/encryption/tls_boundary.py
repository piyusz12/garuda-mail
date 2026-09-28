"""
app/encryption/tls_boundary.py

Determines the exact stream offset/direction/timestamp where plaintext
application data ends and TLS begins, and distinguishes:

  - STARTTLS-driven transition: plaintext commands precede the boundary
  - Implicit TLS: the TLS ClientHello is (almost) the first thing seen
    on the wire, with no plaintext application protocol beforehand

Ports (465/993/995) are only ever a weak hint here too -- the actual
determination is "did we see a TLS record at/near offset 0".
"""

from __future__ import annotations

from app.models.encryption_event import TLSBoundary
from app.models.protocol_event import Direction, EventType, ProtocolEvent

IMPLICIT_TLS_OFFSET_TOLERANCE = 0  # ClientHello must be the very first bytes


def find_tls_client_hello(events: list[ProtocolEvent]) -> ProtocolEvent | None:
    for event in events:
        if event.event_type == EventType.TLS_CLIENT_HELLO:
            return event
    return None


def build_boundary(event: ProtocolEvent) -> TLSBoundary:
    return TLSBoundary(
        direction=event.direction.value,
        stream_offset=event.stream_offset,
        timestamp=event.timestamp,
    )


def is_implicit_tls(hello_event: ProtocolEvent, plaintext_events: list[ProtocolEvent]) -> bool:
    """True when no plaintext application-layer command/greeting precedes
    the ClientHello on the same directional stream -- i.e. TLS started
    at (or essentially at) byte 0, rather than after a STARTTLS upgrade."""
    if hello_event.direction != Direction.C2S:
        # Implicit TLS is judged from the client's first bytes.
        return hello_event.stream_offset <= IMPLICIT_TLS_OFFSET_TOLERANCE
    preceding_plaintext = [
        e for e in plaintext_events
        if e.direction == Direction.C2S and e.stream_offset < hello_event.stream_offset
    ]
    return hello_event.stream_offset <= IMPLICIT_TLS_OFFSET_TOLERANCE and not preceding_plaintext
