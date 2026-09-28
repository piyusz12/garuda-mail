# Phase 2 — Email Protocol Identification & Encryption Transition Analysis

This implements Phase 2 of the email forensic framework: given a
reconstructed TCP session (Phase 1's output), determine

1. **which application protocol** it is (SMTP / IMAP / POP3 / UNKNOWN),
   without relying on port numbers alone,
2. **its application state** (greeting, capability negotiation, auth,
   mail transaction, logout, ...),
3. **its encryption transition** — STARTTLS/STLS offered / requested /
   accepted / rejected, or implicit TLS, and
4. **the exact stream offset** where plaintext ends and TLS begins.

It deliberately stops there: no X.509 parsing, no JA4, no risk scoring.
Those belong to Phase 3 onward.

## Layout

```
app/
  models/            ReconstructedSession, ProtocolEvent, EncryptionTransition
  protocol/
    detector.py      Phase 2 entry point: analyze_session(session) -> ProtocolAnalysis
    classifier.py     payload-signature scoring across SMTP/IMAP/POP3, port conflicts
    confidence.py     HIGH/MEDIUM/LOW bucketing
    common.py         shared line tokenizer + TLS record sniffing
    smtp/ imap/ pop3/  per-protocol signatures.py, state_machine.py, parser.py
  encryption/
    starttls.py        STARTTLS/STLS status extraction from events
    tls_boundary.py     implicit-vs-STARTTLS TLS boundary detection
    transition_detector.py  aggregates the above into EncryptionTransition
                             + observation-level security indicators
  storage/writer.py   writes output/analysis/<session_id>.json

tests/                17 tests covering normal traffic, non-standard ports,
                       fragmentation, pipelining, STARTTLS success/failure/
                       unused, plaintext auth, port/payload conflicts,
                       truncated streams, and exact TLS-boundary offsets

run_phase2.py         demo runner: 8 synthetic sessions -> printed summary
                       + timeline + JSON written to output/analysis/
```

## Running

```bash
python3 run_phase2.py     # demo against synthetic sessions
python3 -m pytest -q      # test suite
```

## Wiring into Phase 1

Replace `tests.fixtures.build_session` calls with real
`ReconstructedSession` objects coming out of `app/reassembly`, then call:

```python
from app.protocol.detector import analyze_session
from app.storage.writer import write_analysis

analysis = analyze_session(reconstructed_session)
write_analysis(analysis)
```

## Output contract (consumed by Phase 3)

```json
{
  "session_id": "FLOW-00042",
  "protocol": {"name": "SMTP", "confidence": 0.99, "confidence_bucket": "HIGH", "evidence": [...]},
  "port_hint": "SMTP",
  "port_protocol_conflict": false,
  "state": "ENCRYPTED",
  "encryption": {
    "mode": "STARTTLS",
    "offered": true, "requested": true, "accepted": true, "rejected": false,
    "tls_detected": true,
    "boundary": {"direction": "client_to_server", "offset": 1847, "timestamp": 1719999999.1},
    "security_indicators": []
  },
  "events": [ { "timestamp": ..., "direction": "...", "event_type": "...", "evidence": "..." }, ... ],
  "parse_status": "COMPLETE"
}
```

## Design notes / what was implemented from the spec

- **No port-only classification** (§3): every scorer in `*/signatures.py`
  weighs payload signatures first; a matching port only adds a small
  (+0.05) bonus, and a mismatch is reported as `port_protocol_conflict`
  rather than silently overridden (§28).
- **State machines** (§10) per protocol track GREETING → COMMAND/CAPABILITY
  → STARTTLS_REQUESTED → TLS_NEGOTIATION → ENCRYPTED (SMTP), and the
  IMAP/POP3 equivalents.
- **Directional streams parsed separately and correlated** (§11) via
  `Direction.C2S` / `Direction.S2C` tagged events sorted by timestamp.
- **Fragmentation & pipelining** (§23–25) are handled because the parsers
  operate on the *reassembled* stream via `iter_lines_with_offsets`, not
  per-packet — verified by dedicated fragmentation tests.
- **STARTTLS full lifecycle** (§13–16): offered / requested / accepted /
  rejected are tracked independently so "offered but never used" and
  "requested but rejected" are distinguishable, each raising its own
  security indicator.
- **Exact TLS boundary** (§16, §37): `tls_boundary.py` records the byte
  offset/direction/timestamp of the TLS record, and tests assert that
  bytes before it are plaintext and bytes from it onward are a valid
  TLS record header — not just `tls_detected == True`.
- **Implicit vs. STARTTLS TLS** (§17): `is_implicit_tls` distinguishes a
  ClientHello at offset 0 (implicit TLS, e.g. ports 465/993/995) from
  one following plaintext commands (STARTTLS-driven).
- **Credential redaction** (§21–22): `redact_if_sensitive` never stores
  AUTH/USER/PASS/LOGIN payloads — only that the command occurred.
- **Malformed/truncated streams** (§26): `ReconstructedSession.truncated`
  flows through to `parse_status: "PARTIAL"` instead of raising.
- **Observation → indicator, not risk** (§40–41): `transition_detector.py`
  only emits `security_indicators` with a `severity_hint`; no overall
  risk score, no ML, no X.509/JA4 — those are explicitly out of scope
  per §41 and left for later phases.
