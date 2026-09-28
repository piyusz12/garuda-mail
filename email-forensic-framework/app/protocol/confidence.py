"""
app/protocol/confidence.py

Turns a numeric classifier score into a HIGH/MEDIUM/LOW bucket for
human-readable reporting. This is classifier confidence, not a claim
about the true probability the traffic is that protocol.
"""

from __future__ import annotations

HIGH_THRESHOLD = 0.95
MEDIUM_THRESHOLD = 0.75


def bucket(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
