"""
app/protocol/classifier.py

Scores a session against every known protocol's signature set and picks
the best match. Port numbers are only ever a small bonus inside each
protocol's own scoring function (see */signatures.py) -- never the sole
basis for identification, per the project spec (section 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.protocol.imap import signatures as imap_sig
from app.protocol.pop3 import signatures as pop3_sig
from app.protocol.smtp import signatures as smtp_sig

MIN_CONFIDENCE_FOR_MATCH = 0.30

_SCORERS = {
    "SMTP": smtp_sig.score,
    "IMAP": imap_sig.score,
    "POP3": pop3_sig.score,
}

_PORT_HINT_PROTOCOL = {
    25: "SMTP", 587: "SMTP", 465: "SMTP",
    143: "IMAP", 993: "IMAP",
    110: "POP3", 995: "POP3",
}


@dataclass
class ProtocolDetectionResult:
    protocol: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    port_hint: str | None = None
    port_protocol_conflict: bool = False
    all_scores: dict = field(default_factory=dict)


def classify(session) -> ProtocolDetectionResult:
    scores: dict[str, tuple[float, list[str]]] = {}
    for name, scorer in _SCORERS.items():
        scores[name] = scorer(
            session.client_to_server, session.server_to_client,
            session.dst_port, session.src_port,
        )

    best_protocol, (best_score, best_evidence) = max(scores.items(), key=lambda kv: kv[1][0])

    port_hint = _PORT_HINT_PROTOCOL.get(session.dst_port) or _PORT_HINT_PROTOCOL.get(session.src_port)

    if best_score < MIN_CONFIDENCE_FOR_MATCH:
        return ProtocolDetectionResult(
            protocol="UNKNOWN",
            confidence=round(best_score, 3),
            evidence=best_evidence,
            port_hint=port_hint,
            port_protocol_conflict=False,
            all_scores={k: round(v[0], 3) for k, v in scores.items()},
        )

    conflict = bool(port_hint and port_hint != best_protocol)

    return ProtocolDetectionResult(
        protocol=best_protocol,
        confidence=round(best_score, 3),
        evidence=best_evidence,
        port_hint=port_hint,
        port_protocol_conflict=conflict,
        all_scores={k: round(v[0], 3) for k, v in scores.items()},
    )
