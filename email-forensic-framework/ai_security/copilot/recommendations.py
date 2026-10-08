from __future__ import annotations

from typing import Any, Dict, List

from ai_security.copilot.schemas import Recommendation


class RecommendationEngine:
    """Create SOAR-ready recommendations from investigation evidence."""

    def generate(self, entity_id: str, evidence: List[Dict[str, Any]] | None = None, case_id: str = "CASE-1042") -> List[Recommendation]:
        evidence = evidence or []
        reasons = ["TLS downgrade detected", "Rare JA4 signature", "Certificate mismatch"]
        if evidence:
            reasons = [item.get("description", "") for item in evidence[:3] if item.get("description")]

        return [
            Recommendation(
                recommendation_id="REC-1042",
                case_id=case_id,
                target=entity_id,
                recommended_action="QUARANTINE_ASSET",
                reason=reasons,
                risk_class="R3_POTENTIAL_IMPACT",
                requires_approval=True,
                rollback_available=True,
                security_gain="HIGH",
                operational_impact="LOW",
                confidence=0.96,
            ),
            Recommendation(
                recommendation_id="REC-1043",
                case_id=case_id,
                target=entity_id,
                recommended_action="ROTATE_CERTIFICATE",
                reason=["Unexpected certificate mismatch and legacy TLS exposure"],
                risk_class="R2_CONTAINMENT",
                requires_approval=True,
                rollback_available=True,
                security_gain="MEDIUM",
                operational_impact="LOW",
                confidence=0.9,
            ),
        ]


__all__ = ["RecommendationEngine"]
