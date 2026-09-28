"""
app/protocol/imap/signatures.py

IMAP command tags are client-chosen and arbitrary (A001, X1, ...), so
every command regex here matches "<tag> COMMAND" generically rather
than hard-coding a tag scheme, per the project spec (section 7).
"""

from __future__ import annotations

import re

TAG = rb"[A-Za-z0-9]+"

UNTAGGED_OK_RE = re.compile(rb"^\* (OK|PREAUTH)\b", re.IGNORECASE | re.MULTILINE)
CAPABILITY_UNTAGGED_RE = re.compile(rb"^\* CAPABILITY\b", re.IGNORECASE | re.MULTILINE)
TAGGED_CMD_RE = re.compile(
    TAG + rb"[ \t]+(CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|LOGOUT)\b",
    re.IGNORECASE | re.MULTILINE,
)
TAGGED_CAPABILITY_RE = re.compile(TAG + rb"[ \t]+CAPABILITY\b", re.IGNORECASE | re.MULTILINE)
TAGGED_STARTTLS_RE = re.compile(TAG + rb"[ \t]+STARTTLS\b", re.IGNORECASE | re.MULTILINE)
TAGGED_LOGIN_RE = re.compile(TAG + rb"[ \t]+LOGIN\b", re.IGNORECASE | re.MULTILINE)
TAGGED_LOGOUT_RE = re.compile(TAG + rb"[ \t]+LOGOUT\b", re.IGNORECASE | re.MULTILINE)
TAGGED_OK_RESPONSE_RE = re.compile(TAG + rb"[ \t]+OK\b", re.IGNORECASE | re.MULTILINE)
STARTTLS_IN_CAPABILITY_RE = re.compile(rb"CAPABILITY[^\r\n]*\bSTARTTLS\b", re.IGNORECASE)

KNOWN_PORTS = {143, 993}

SCORING_RULES = [
    (UNTAGGED_OK_RE, 0.35, "untagged_ok_greeting"),
    (TAGGED_CMD_RE, 0.30, "tagged_command"),
    (CAPABILITY_UNTAGGED_RE, 0.20, "untagged_capability"),
    (TAGGED_LOGIN_RE, 0.15, "tagged_login"),
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
        evidence.append("known_imap_port")
    return min(total, 1.0), evidence
