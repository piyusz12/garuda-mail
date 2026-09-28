"""
tests/fixtures.py

Builds ReconstructedSession objects out of a simple scripted
conversation, so tests and the demo runner don't need real PCAPs.
"""

from __future__ import annotations

import time

from app.models.session import ReconstructedSession

TLS_CLIENT_HELLO_BYTES = bytes([0x16, 0x03, 0x01, 0x00, 0x2F, 0x01]) + b"\x00" * 40


def build_session(session_id: str, dst_port: int, script: list[tuple[str, bytes]],
                   src_port: int = 53241, truncated: bool = False,
                   fragment_first: bool = False) -> ReconstructedSession:
    """`script` is a list of ("c2s"|"s2c", line_bytes_with_or_without_crlf) tuples,
    applied in order with strictly increasing timestamps.

    If fragment_first is True, the first "c2s" entry is split into two
    chunks mid-command to exercise fragmentation handling.
    """
    session = ReconstructedSession(
        session_id=session_id,
        src_ip="10.0.0.15", src_port=src_port,
        dst_ip="203.0.113.20", dst_port=dst_port,
        truncated=truncated,
    )
    t = time.time()
    fragmented_done = not fragment_first

    for direction, raw in script:
        if not raw.endswith(b"\r\n") and not raw.startswith(bytes([0x16])):
            raw = raw + b"\r\n"
        t += 0.01
        if direction == "c2s" and not fragmented_done:
            mid = len(raw) // 2 or 1
            session.add_c2s(raw[:mid], t)
            t += 0.005
            session.add_c2s(raw[mid:], t)
            fragmented_done = True
        elif direction == "c2s":
            session.add_c2s(raw, t)
        else:
            session.add_s2c(raw, t)

    return session
