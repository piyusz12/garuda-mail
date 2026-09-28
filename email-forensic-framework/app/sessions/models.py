"""
app/sessions/models.py

Core data models for Phase 6: Stateful Email Sessions.

Defines the common structures used across SMTP, IMAP, and POP3
session reconstruction. These are the output contracts that downstream
phases (7–14) consume.

Design decisions:
- Uses dataclasses (not Pydantic) for the session internals to keep
  things lightweight during stateful processing. A .to_dict() method
  produces the JSON-serializable output for export / Phase 7+.
- SessionEvent carries both the normalized event type AND the raw
  evidence so later phases can drill down if needed.
- SecurityContext is a flat struct that records *what happened*,
  not *whether it's a violation* (that's Phase 14's job).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ─── Session Event ──────────────────────────────────────────────────

@dataclass
class SessionEvent:
    """A single protocol-level event inside an email session."""

    timestamp: float
    direction: str                  # "client_to_server" | "server_to_client"
    event_type: str                 # Normalized event name (e.g. "EHLO", "STARTTLS_ACCEPTED")
    raw_data: str = ""              # Sanitised evidence snippet (credentials redacted)
    stream_offset: int = 0          # Byte offset in the direction's stream
    sequence: int = 0               # Monotonic order within the session

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "type": self.event_type,
            "raw_data": self.raw_data,
            "stream_offset": self.stream_offset,
            "sequence": self.sequence,
        }


# ─── Security Context ──────────────────────────────────────────────

@dataclass
class SecurityContext:
    """
    Records security-relevant *facts* observed during the session.

    Phase 6 populates these fields.  Phase 14 interprets them as
    security findings.
    """

    # STARTTLS lifecycle
    starttls_advertised: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    starttls_rejected: bool = False
    tls_started: bool = False

    # Authentication observations
    authentication_attempted: bool = False
    authentication_before_tls: bool = False
    auth_mechanism: Optional[str] = None

    # Mail transaction observations
    mail_from: Optional[str] = None
    rcpt_to: list[str] = field(default_factory=list)
    data_started: bool = False

    # Capability advertisement
    advertised_capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "starttls_advertised": self.starttls_advertised,
            "starttls_requested": self.starttls_requested,
            "starttls_accepted": self.starttls_accepted,
            "starttls_rejected": self.starttls_rejected,
            "tls_started": self.tls_started,
            "authentication_attempted": self.authentication_attempted,
            "authentication_before_tls": self.authentication_before_tls,
        }
        if self.auth_mechanism:
            d["auth_mechanism"] = self.auth_mechanism
        if self.mail_from:
            d["mail_from"] = self.mail_from
        if self.rcpt_to:
            d["rcpt_to"] = self.rcpt_to
        if self.data_started:
            d["data_started"] = True
        if self.advertised_capabilities:
            d["advertised_capabilities"] = self.advertised_capabilities
        return d


# ─── Email Session ──────────────────────────────────────────────────

@dataclass
class EmailSession:
    """
    A fully-reconstructed, stateful email session.

    This is the primary output of Phase 6.  One EmailSession corresponds
    to one TCP flow that carried an email protocol conversation.
    """

    session_id: str
    protocol: str                   # "SMTP" | "IMAP" | "POP3"

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    # State machine
    state: str = "TCP_CONNECTED"
    mode: str = "PLAINTEXT"         # "PLAINTEXT" | "TLS" | "IMPLICIT_TLS"

    # Timestamps
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    # Ordered event log
    events: list[SessionEvent] = field(default_factory=list)

    # Security context (facts, not judgements)
    security: SecurityContext = field(default_factory=SecurityContext)

    # Error / anomaly tracking
    parse_warnings: list[str] = field(default_factory=list)

    # Internal counter for event sequencing
    _event_seq: int = field(default=0, repr=False)

    # ── helpers ──

    def add_event(self, event: SessionEvent) -> None:
        """Append an event with automatic sequencing and time tracking."""
        self._event_seq += 1
        event.sequence = self._event_seq

        if self.start_time is None or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if self.end_time is None or event.timestamp > self.end_time:
            self.end_time = event.timestamp

        self.events.append(event)

    @property
    def duration_ms(self) -> float:
        if self.start_time is not None and self.end_time is not None:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    @property
    def timeline(self) -> list[str]:
        """Human-readable event timeline relative to session start."""
        if not self.events or self.start_time is None:
            return []
        lines: list[str] = []
        for ev in self.events:
            delta = ev.timestamp - self.start_time
            minutes, seconds = divmod(delta, 60)
            millis = int((seconds % 1) * 1000)
            lines.append(
                f"{int(minutes):02d}:{int(seconds):02d}.{millis:03d}  "
                f"{ev.event_type}"
            )
        return lines

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict (Phase 6 output contract)."""
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "client": {
                "ip": self.client_ip,
                "port": self.client_port,
            },
            "server": {
                "ip": self.server_ip,
                "port": self.server_port,
            },
            "state": self.state,
            "mode": self.mode,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration_ms, 3),
            "events": [e.to_dict() for e in self.events],
            "security_context": self.security.to_dict(),
            "parse_warnings": self.parse_warnings,
        }

    def summary(self) -> str:
        """Pretty-print a session summary for CLI / debugging."""
        lines = [
            "=" * 56,
            "EMAIL SESSION",
            "=" * 56,
            "",
            f"Session ID : {self.session_id}",
            f"Protocol   : {self.protocol}",
            "",
            f"Client     : {self.client_ip}:{self.client_port}",
            f"Server     : {self.server_ip}:{self.server_port}",
            "",
            "Timeline",
            "-" * 56,
        ]
        for i, tl in enumerate(self.timeline, 1):
            lines.append(f"  {i:>2}. {tl}")

        sec = self.security
        lines += [
            "",
            "Security Context",
            "-" * 56,
            f"  STARTTLS advertised     : {'YES' if sec.starttls_advertised else 'NO'}",
            f"  STARTTLS requested      : {'YES' if sec.starttls_requested else 'NO'}",
            f"  STARTTLS accepted       : {'YES' if sec.starttls_accepted else 'NO'}",
            f"  STARTTLS rejected       : {'YES' if sec.starttls_rejected else 'NO'}",
            f"  TLS started             : {'YES' if sec.tls_started else 'NO'}",
            f"  Auth attempted          : {'YES' if sec.authentication_attempted else 'NO'}",
            f"  Auth before TLS         : {'YES' if sec.authentication_before_tls else 'NO'}",
            "",
            f"Final State : {self.state}",
            f"Mode        : {self.mode}",
        ]

        if self.parse_warnings:
            lines += ["", "Warnings"]
            for w in self.parse_warnings:
                lines.append(f"  ⚠ {w}")

        lines.append("=" * 56)
        return "\n".join(lines)
