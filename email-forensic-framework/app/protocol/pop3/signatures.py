"""app/protocol/pop3/signatures.py"""

from __future__ import annotations

import re

POSITIVE_GREETING_RE = re.compile(rb"^\+OK\b", re.MULTILINE)
USER_CMD_RE = re.compile(rb"^USER\b", re.IGNORECASE | re.MULTILINE)
PASS_CMD_RE = re.compile(rb"^PASS\b", re.IGNORECASE | re.MULTILINE)
STLS_CMD_RE = re.compile(rb"^STLS\b", re.IGNORECASE | re.MULTILINE)
CAPA_CMD_RE = re.compile(rb"^CAPA\b", re.IGNORECASE | re.MULTILINE)
STLS_IN_CAPA_RE = re.compile(rb"^STLS\b", re.IGNORECASE | re.MULTILINE)
NEGATIVE_RE = re.compile(rb"^-ERR\b", re.MULTILINE)

KNOWN_PORTS = {110, 995}

SCORING_RULES = [
    (POSITIVE_GREETING_RE, 0.35, "positive_ok_greeting"),
    (USER_CMD_RE, 0.25, "user_command"),
    (PASS_CMD_RE, 0.20, "pass_command"),
    (CAPA_CMD_RE, 0.10, "capa_command"),
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
        evidence.append("known_pop3_port")
    return min(total, 1.0), evidence
