"""
app/transition/models.py

Data models for Phase 7: TLS Transition Analysis.

Two main structures:

  TransitionEvidence  — a single piece of forensic evidence supporting
                        a Phase 7 conclusion.
  TLSUpgradeResult    — the complete Phase 7 output for one email session.

Design decisions:
  - Every boolean conclusion carries an evidence trail so the result
    is independently auditable (forensic requirement).
  - `confidence` is NOT a statistical probability.  It's a heuristic
    reflecting how much of the expected protocol exchange was actually
    observed in the capture.
  - `transition_status` uses a controlled vocabulary defined in rules.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ─── Transition Evidence ────────────────────────────────────────────

@dataclass
class TransitionEvidence:
    """
    One piece of evidence supporting a Phase 7 conclusion.

    Example:
        TransitionEvidence(
            event_type="STARTTLS_ACCEPTED",
            raw_data="220 2.0.0 Ready to start TLS",
            timestamp=172.815,
            stream_offset=1031,
            direction="server_to_client",
            description="Server accepted STARTTLS upgrade"
        )
    """

    event_type: str
    timestamp: Optional[float] = None
    stream_offset: Optional[int] = None
    direction: Optional[str] = None
    raw_data: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.event_type}
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.stream_offset is not None:
            d["stream_offset"] = self.stream_offset
        if self.direction:
            d["direction"] = self.direction
        if self.raw_data:
            d["raw_data"] = self.raw_data
        if self.description:
            d["description"] = self.description
        return d


# ─── Authentication Timing ──────────────────────────────────────────

@dataclass
class AuthenticationTiming:
    """Records when authentication happened relative to TLS."""

    before_tls: bool = False
    after_tls: bool = False

    # Timestamps for forensic precision
    auth_timestamp: Optional[float] = None
    tls_timestamp: Optional[float] = None
    auth_mechanism: Optional[str] = None

    # How many milliseconds between auth and TLS
    # Negative = auth happened before TLS
    delta_ms: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "before_tls": self.before_tls,
            "after_tls": self.after_tls,
        }
        if self.auth_timestamp is not None:
            d["auth_timestamp"] = self.auth_timestamp
        if self.tls_timestamp is not None:
            d["tls_timestamp"] = self.tls_timestamp
        if self.auth_mechanism:
            d["auth_mechanism"] = self.auth_mechanism
        if self.delta_ms is not None:
            d["delta_ms"] = round(self.delta_ms, 3)
        return d


# ─── TLS Upgrade Result ────────────────────────────────────────────

@dataclass
class TLSUpgradeResult:
    """
    The complete Phase 7 output for one email session.

    This is the contract that Phase 8 (TLS Handshake Analysis)
    consumes.
    """

    session_id: str
    protocol: str                           # "SMTP" | "IMAP" | "POP3"

    # ── TLS mode ──
    tls_mode: str = "UNKNOWN"               # "STARTTLS" | "IMPLICIT_TLS" | "PLAINTEXT" | "UNKNOWN"

    # ── STARTTLS lifecycle booleans ──
    capability_advertised: Optional[bool] = None
    tls_requested: Optional[bool] = None
    tls_accepted: Optional[bool] = None
    tls_handshake_observed: Optional[bool] = None

    # ── Authentication relative to TLS ──
    authentication: AuthenticationTiming = field(
        default_factory=AuthenticationTiming
    )

    # ── Post-TLS anomaly ──
    plaintext_after_tls: bool = False

    # ── Final classification ──
    transition_status: str = "UNKNOWN"      # Controlled vocabulary from rules.py
    confidence: float = 0.0

    # ── Evidence trail ──
    evidence: list[TransitionEvidence] = field(default_factory=list)

    # ── Warnings / anomalies ──
    warnings: list[str] = field(default_factory=list)

    def add_evidence(self, ev: TransitionEvidence) -> None:
        """Append a piece of evidence."""
        self.evidence.append(ev)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the Phase 7 JSON output contract."""
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "tls": {
                "mode": self.tls_mode,
                "capability_advertised": self.capability_advertised,
                "requested": self.tls_requested,
                "accepted": self.tls_accepted,
                "handshake_observed": self.tls_handshake_observed,
                "authentication": self.authentication.to_dict(),
                "plaintext_after_tls": self.plaintext_after_tls,
                "transition_status": self.transition_status,
            },
            "evidence": [e.to_dict() for e in self.evidence],
            "confidence": round(self.confidence, 2),
            "warnings": self.warnings,
        }

    def summary(self) -> str:
        """Pretty-print for CLI / debugging."""
        lines = [
            "=" * 56,
            "PHASE 7 — TLS TRANSITION ANALYSIS",
            "=" * 56,
            "",
            f"Session    : {self.session_id}",
            f"Protocol   : {self.protocol}",
            f"TLS Mode   : {self.tls_mode}",
            "",
        ]

        def _yn(val: Optional[bool]) -> str:
            if val is None:
                return "N/A"
            return "YES" if val else "NO"

        lines += [
            f"STARTTLS Advertised    : {_yn(self.capability_advertised)}",
            f"STARTTLS Requested     : {_yn(self.tls_requested)}",
            f"STARTTLS Accepted      : {_yn(self.tls_accepted)}",
            f"TLS Handshake Observed : {_yn(self.tls_handshake_observed)}",
            "",
            "Authentication",
            "-" * 56,
            f"  Before TLS : {'YES' if self.authentication.before_tls else 'NO'}",
            f"  After TLS  : {'YES' if self.authentication.after_tls else 'NO'}",
        ]

        if self.authentication.auth_mechanism:
            lines.append(f"  Mechanism  : {self.authentication.auth_mechanism}")
        if self.authentication.delta_ms is not None:
            lines.append(f"  Delta      : {self.authentication.delta_ms:.1f} ms")

        lines += [
            "",
            f"Plaintext After TLS : {'YES' if self.plaintext_after_tls else 'NO'}",
            "",
            f"Transition Status   : {self.transition_status}",
            f"Confidence          : {self.confidence * 100:.0f}%",
        ]

        if self.evidence:
            lines += ["", "Evidence", "-" * 56]
            for ev in self.evidence:
                ts = f" @ {ev.timestamp:.3f}" if ev.timestamp else ""
                lines.append(f"  {ev.event_type}{ts} : {ev.description}")

        if self.warnings:
            lines += ["", "Warnings", "-" * 56]
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")

        lines.append("=" * 56)
        return "\n".join(lines)
