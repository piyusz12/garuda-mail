"""
app/protocol/common.py

Small utilities shared by the SMTP/IMAP/POP3 parsers:

  - `iter_lines_with_offsets`: splits a reassembled byte stream into
    CRLF-delimited logical lines, each tagged with its start offset in
    the stream. Handles pipelining (multiple commands per read) and
    fragmentation (a command split across chunks) correctly because it
    operates on the *already reassembled* stream, not per-packet data.

  - `looks_like_tls_record`: enough of RFC 8446 record-layer structure
    to recognize "a TLS handshake starts here" without doing any real
    TLS parsing (that's Phase 3's job).
"""

from __future__ import annotations

from collections.abc import Iterator

CRLF = b"\r\n"


def iter_lines_with_offsets(stream: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (start_offset, line_bytes_without_crlf) for each complete
    line in `stream`. A trailing partial line (no CRLF yet) is dropped --
    callers that need partial-command handling should re-run this once
    more bytes arrive; Phase 2's batch analysis just accepts the small
    loss of an incomplete final line and flags parse_status accordingly.
    """
    start = 0
    while True:
        idx = stream.find(CRLF, start)
        if idx == -1:
            # Also tolerate bare \n for lenient/malformed captures.
            idx_lf = stream.find(b"\n", start)
            if idx_lf == -1:
                return
            yield start, stream[start:idx_lf].rstrip(b"\r")
            start = idx_lf + 1
            continue
        yield start, stream[start:idx]
        start = idx + len(CRLF)


# TLS content type 0x16 = Handshake, versions 3.1-3.3 cover TLS1.0-1.2
# (TLS1.3 also negotiates via a 3.3 "legacy" record for compatibility),
# followed by handshake type 0x01 = ClientHello.
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_LEGACY_VERSIONS = {(3, 1), (3, 2), (3, 3)}
_TLS_HANDSHAKE_CLIENT_HELLO = 0x01


def looks_like_tls_record(data: bytes) -> bool:
    """Heuristic: does `data` begin with a TLS record header wrapping a
    ClientHello handshake message? This is intentionally shallow --
    Phase 3 owns full TLS parsing."""
    if len(data) < 6:
        return False
    content_type = data[0]
    version = (data[1], data[2])
    handshake_type = data[5]
    return (
        content_type == _TLS_CONTENT_TYPE_HANDSHAKE
        and version in _TLS_LEGACY_VERSIONS
        and handshake_type == _TLS_HANDSHAKE_CLIENT_HELLO
    )


def redact_if_sensitive(command: str, line: bytes) -> str:
    """Return a printable, possibly-redacted evidence string for a line.
    Credentials are never retained -- only the fact that auth occurred."""
    sensitive_prefixes = (b"AUTH", b"PASS", b"LOGIN")
    upper = line.upper()
    if any(upper.startswith(p) for p in sensitive_prefixes):
        return f"{command} [REDACTED]"
    try:
        text = line.decode("utf-8", errors="replace")
    except Exception:
        text = repr(line)
    return text[:120]
