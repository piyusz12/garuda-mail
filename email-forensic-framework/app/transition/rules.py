"""
app/transition/rules.py

Controlled vocabulary and classification rules for Phase 7.

Defines:
  - TRANSITION_STATUS values (the final label for a session)
  - TLS_MODE values
  - Protocol-specific command mappings
  - The decision table that maps observed facts to a transition status

These are separated from the detection logic so they can be reviewed,
audited, and extended independently.
"""

from __future__ import annotations


# ─── TLS Mode ──────────────────────────────────────────────────────

class TLSMode:
    """How TLS was (or wasn't) initiated."""
    STARTTLS = "STARTTLS"                   # Explicit upgrade via STARTTLS/STLS
    IMPLICIT_TLS = "IMPLICIT_TLS"           # TLS from first byte (ports 465, 993, 995)
    PLAINTEXT = "PLAINTEXT"                 # No TLS observed at all
    UNKNOWN = "UNKNOWN"                     # Cannot determine


# ─── Transition Status ─────────────────────────────────────────────

class TransitionStatus:
    """
    Controlled vocabulary for the final transition classification.

    These are FACTS about what happened, not severity judgements.
    Phase 14 maps these to security findings.
    """

    # ── Success cases ──
    IMPLICIT_TLS = "IMPLICIT_TLS"
    """Connection started directly with TLS (e.g. port 465/993/995)."""

    STARTTLS_SUCCESS = "STARTTLS_SUCCESS"
    """STARTTLS advertised → requested → accepted → TLS handshake observed."""

    # ── Partial / degraded cases ──
    STARTTLS_AVAILABLE_NOT_USED = "STARTTLS_AVAILABLE_NOT_USED"
    """Server advertised STARTTLS, client never requested it."""

    STARTTLS_REJECTED = "STARTTLS_REJECTED"
    """Client requested STARTTLS, server refused (454, NO, -ERR, etc.)."""

    STARTTLS_ACCEPTED_NO_HANDSHAKE = "STARTTLS_ACCEPTED_NO_HANDSHAKE"
    """Server accepted STARTTLS (220/OK/+OK) but no TLS handshake was observed."""

    TLS_NEGOTIATION_FAILED = "TLS_NEGOTIATION_FAILED"
    """TLS handshake began but appears incomplete or broken."""

    PLAINTEXT_AFTER_TLS = "PLAINTEXT_AFTER_TLS"
    """Recognizable plaintext appeared after TLS was supposedly established."""

    # ── Informational ──
    PLAINTEXT_SESSION = "PLAINTEXT_SESSION"
    """No STARTTLS capability advertised and no TLS observed. Pure plaintext."""

    STARTTLS_NOT_OBSERVED = "STARTTLS_NOT_OBSERVED"
    """No STARTTLS in capabilities. Could be stripping or simply not offered."""

    INCOMPLETE_CAPTURE = "INCOMPLETE_CAPTURE"
    """PCAP data is insufficient to determine the transition outcome."""

    UNKNOWN = "UNKNOWN"
    """Cannot classify."""


# ─── Protocol Command Mappings ─────────────────────────────────────

TLS_UPGRADE_COMMANDS = {
    "SMTP": "STARTTLS",
    "IMAP": "STARTTLS",
    "POP3": "STLS",
}

TLS_ACCEPT_EVENTS = {
    "SMTP": {"STARTTLS_ACCEPTED"},
    "IMAP": {"STARTTLS_ACCEPTED"},
    "POP3": {"STLS_ACCEPTED"},
}

TLS_REJECT_EVENTS = {
    "SMTP": {"STARTTLS_REJECTED"},
    "IMAP": {"STARTTLS_REJECTED"},
    "POP3": {"STLS_REJECTED"},
}

TLS_REQUEST_EVENTS = {
    "SMTP": {"STARTTLS_REQUESTED"},
    "IMAP": {"STARTTLS_REQUESTED"},
    "POP3": {"STLS_REQUESTED"},
}

TLS_ADVERTISE_EVENTS = {
    "SMTP": {"STARTTLS_ADVERTISED"},
    "IMAP": {"STARTTLS_ADVERTISED"},
    "POP3": {"STARTTLS_ADVERTISED"},      # POP3 parser emits this for STLS in CAPA
}

AUTH_EVENTS = {
    "SMTP": {"AUTH_ATTEMPT"},
    "IMAP": {"AUTH_ATTEMPT"},              # LOGIN and AUTHENTICATE
    "POP3": {"AUTH_ATTEMPT"},              # USER, PASS, AUTH
}

# ── Implicit TLS ports (RFC 8314) ──
IMPLICIT_TLS_PORTS = {465, 993, 995}


# ─── Confidence Weights ────────────────────────────────────────────

# Each piece of observed evidence contributes to the confidence score.
# These are heuristic weights, NOT calibrated probabilities.

CONFIDENCE_WEIGHTS = {
    "capability_advertised": 0.10,
    "tls_requested": 0.15,
    "tls_accepted": 0.20,
    "tls_handshake_observed": 0.30,
    "tls_rejected": 0.20,
    "implicit_tls": 0.25,
    "auth_timing_determined": 0.05,
}

# Minimum confidence for a conclusion to be considered reliable
CONFIDENCE_THRESHOLD_RELIABLE = 0.70
CONFIDENCE_THRESHOLD_PARTIAL = 0.40
