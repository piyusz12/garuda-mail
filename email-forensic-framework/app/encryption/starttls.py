"""
app/encryption/starttls.py

Reduces a session's ProtocolEvent list down to STARTTLS/STLS status
booleans (offered/requested/accepted/rejected), independent of which
protocol produced them -- SMTP STARTTLS, IMAP STARTTLS, and POP3 STLS
all normalize to the same shape here.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.protocol_event import EventType, ProtocolEvent


@dataclass
class StarttlsStatusFlags:
    offered: bool = False
    requested: bool = False
    accepted: bool = False
    rejected: bool = False


def extract_starttls_status(events: list[ProtocolEvent]) -> StarttlsStatusFlags:
    flags = StarttlsStatusFlags()
    for event in events:
        if event.event_type == EventType.STARTTLS_OFFER:
            flags.offered = True
        elif event.event_type == EventType.STARTTLS_REQUEST:
            flags.requested = True
        elif event.event_type == EventType.STARTTLS_ACCEPT:
            flags.accepted = True
        elif event.event_type == EventType.STARTTLS_REJECT:
            flags.rejected = True
    return flags
