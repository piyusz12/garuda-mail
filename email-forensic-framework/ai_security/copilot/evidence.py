from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ai_security.copilot.schemas import Evidence


@dataclass
class EvidenceEngine:
    evidence_catalog: List[Evidence] = field(default_factory=list)

    def add(self, evidence: Evidence) -> None:
        self.evidence_catalog.append(evidence)

    def collect(self, entity_id: str, context: Dict[str, Any] | None = None) -> List[Evidence]:
        context = context or {}
        default = [
            Evidence(
                evidence_id="E-001",
                category="TLS",
                description="STARTTLS downgrade detected",
                confidence=0.98,
                source="tls_events",
                references=[entity_id],
            ),
            Evidence(
                evidence_id="E-002",
                category="JA4",
                description="Rare JA4 fingerprint observed in legacy TLS traffic",
                confidence=0.91,
                source="ja4",
                references=[entity_id],
            ),
            Evidence(
                evidence_id="E-003",
                category="CERT",
                description="Certificate mismatch or unexpected certificate chain",
                confidence=0.94,
                source="certificates",
                references=[entity_id],
            ),
        ]
        if self.evidence_catalog:
            return self.evidence_catalog
        return default

    def by_id(self, evidence_id: str) -> Evidence | None:
        for item in self.evidence_catalog:
            if item.evidence_id == evidence_id:
                return item
        return None


__all__ = ["EvidenceEngine", "Evidence"]
