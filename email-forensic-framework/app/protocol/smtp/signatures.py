"""
app/protocol/smtp/signatures.py

Payload signatures and additive scoring for SMTP identification.
Port is only ever a small, optional bonus -- never the deciding factor.
"""

from __future__ import annotations

import re

SERVER_GREETING_RE = re.compile(rb"^220[ \-]", re.MULTILINE)
EHLO_HELO_RE = re.compile(rb"^(EHLO|HELO)\b", re.IGNORECASE | re.MULTILINE)
RESPONSE_250_RE = re.compile(rb"^250[ \-]", re.MULTILINE)
MAIL_FROM_RE = re.compile(rb"^MAIL FROM:", re.IGNORECASE | re.MULTILINE)
RCPT_TO_RE = re.compile(rb"^RCPT TO:", re.IGNORECASE | re.MULTILINE)
DATA_CMD_RE = re.compile(rb"^DATA\b", re.IGNORECASE | re.MULTILINE)
STARTTLS_OFFER_RE = re.compile(rb"^250[ \-]STARTTLS\b", re.IGNORECASE | re.MULTILINE)
STARTTLS_CMD_RE = re.compile(rb"^STARTTLS\b", re.IGNORECASE | re.MULTILINE)
STARTTLS_READY_RE = re.compile(rb"^220[ \-].*(ready|start tls)", re.IGNORECASE | re.MULTILINE)
STARTTLS_FAIL_RE = re.compile(rb"^(454|501|502|503)\b", re.MULTILINE)
AUTH_CMD_RE = re.compile(rb"^AUTH\b", re.IGNORECASE | re.MULTILINE)
QUIT_RE = re.compile(rb"^QUIT\b", re.IGNORECASE | re.MULTILINE)

KNOWN_PORTS = {25, 587, 465}

# (regex, weight, evidence label) -- see project spec section 6.
SCORING_RULES = [
    (SERVER_GREETING_RE, 0.30, "server_220_banner"),
    (EHLO_HELO_RE, 0.30, "client_EHLO"),
    (RESPONSE_250_RE, 0.15, "smtp_250_response"),
    (MAIL_FROM_RE, 0.15, "mail_from"),
    (RCPT_TO_RE, 0.10, "rcpt_to"),
]


def score(c2s: bytes, s2c: bytes, dst_port: int, src_port: int) -> tuple[float, list[str]]:
    evidence: list[str] = []
    total = 0.0
    combined = s2c + b"\n" + c2s
    for pattern, weight, label in SCORING_RULES:
        if pattern.search(combined):
            total += weight
            evidence.append(label)
    if dst_port in KNOWN_PORTS or src_port in KNOWN_PORTS:
        total += 0.05
        evidence.append("known_smtp_port")
    return min(total, 1.0), evidence
