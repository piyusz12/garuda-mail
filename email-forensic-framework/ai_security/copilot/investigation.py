from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ai_security.copilot.context import ContextEngine
from ai_security.copilot.evidence import EvidenceEngine
from ai_security.copilot.guardrails import Guardrails
from ai_security.copilot.intent import classify_intent, resolve_entity
from ai_security.copilot.memory import CopilotMemory
from ai_security.copilot.providers import MockProvider
from ai_security.copilot.reasoning import ReasoningEngine
from ai_security.copilot.recommendations import RecommendationEngine
from ai_security.copilot.schemas import (
    CopilotQuery,
    CopilotResponse,
    Evidence,
    Investigation,
    InvestigationIntent,
    InvestigationTimeline,
    Recommendation,
)
from ai_security.copilot.tools import (
    get_asset_risk,
    get_case,
    get_case_graph,
    get_case_timeline,
    get_mitre_mapping,
    get_similar_incidents,
    search_tls_events,
    simulate_remediation,
)


class AIInvestigationCopilot:
    """Evidence-aware SOC copilot that evaluates security requests against structured telemetry."""

    def __init__(self, provider: Optional[Any] = None):
        self.provider = provider or MockProvider()
        self.context_engine = ContextEngine()
        self.evidence_engine = EvidenceEngine()
        self.reasoning = ReasoningEngine()
        self.guardrails = Guardrails()
        self.recommendation_engine = RecommendationEngine()
        self.memory = CopilotMemory()

    def _default_investigation_id(self) -> str:
        return f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    def generate_hunt_query(self, query: str) -> str:
        q = (query or "").lower()
        if "ja4" in q and "legacy tls" in q:
            return (
                "HUNT rare_ja4_legacy_tls\n"
                "FROM tls_events\n"
                "WHERE tls_version IN ['TLS 1.0', 'TLS 1.1']\n"
                "AND ja4_frequency_90d < 3\n"
                "WITHIN 90d"
            )
        return "HUNT suspicious_activity FROM security_events WITHIN 90d"

    def investigate(
        self,
        query: str,
        tenant_id: str = "TENANT-001",
        analyst_id: str = "ANALYST-07",
        role: str = "SOC_ANALYST",
        permissions: Optional[List[str]] = None,
    ) -> CopilotResponse:
        permissions = permissions or ["read:incidents", "read:sessions", "read:alerts"]
        intent = classify_intent(query)
        entity_id = resolve_entity(query)
        context = self.context_engine.build_context(query, tenant_id, analyst_id, permissions=permissions, entity_id=entity_id)

        if not context.get("authorized", False):
            return CopilotResponse(
                investigation_id=self._default_investigation_id(),
                intent=intent,
                answer="The analyst is not authorized to investigate this tenant scope.",
                risk_level="UNKNOWN",
                confidence=0.0,
                entities=[entity_id],
                evidence=[],
                timeline=[],
                recommendations=[],
                actions=[],
                requires_approval=False,
                citations=[],
            )

        evidence_items = self.evidence_engine.collect(entity_id, context)
        case = get_case()
        timeline = [
            InvestigationTimeline("09:31:03", "Normal SMTP session", "SESSION"),
            InvestigationTimeline("09:32:14", "New destination observed", "NETWORK"),
            InvestigationTimeline("09:32:18", "Legacy TLS characteristics detected", "TLS"),
            InvestigationTimeline("09:32:24", "Detection rule triggered", "DETECTION"),
        ]
        risk = get_asset_risk(entity_id)
        mtre = get_mitre_mapping()
        similar = get_similar_incidents(entity_id)
        explanation = self.reasoning.explain(entity_id, [e.to_dict() for e in evidence_items], [t.to_dict() for t in timeline])
        recs = self.recommendation_engine.generate(entity_id, [e.to_dict() for e in evidence_items], case_id=case.get("case_id", "CASE-1042"))
        response = CopilotResponse(
            investigation_id=self._default_investigation_id(),
            intent=intent,
            answer=explanation,
            risk_level="CRITICAL" if risk.get("score", 0) >= 90 else "HIGH",
            confidence=0.94,
            entities=[entity_id, "203.0.113.77", "mail.example.com"],
            evidence=[item.evidence_id for item in evidence_items],
            timeline=timeline,
            recommendations=[item.recommended_action for item in recs],
            actions=["Investigate sessions", "Review certificate chain", "Escalate to SOAR"],
            requires_approval=True,
            citations=["tls_events:MTA-07", "ja4:JA4-4A4A", f"mitre:{mtre['technique']}"],
        )

        stmt = {
            "investigation_id": response.investigation_id,
            "query": query,
            "tenant_id": tenant_id,
            "analyst_id": analyst_id,
            "intent": response.intent.value,
            "entity_id": entity_id,
            "status": "OPEN",
            "result": explanation,
            "recommendations": [item.to_dict() for item in recs],
            "evidence": [item.to_dict() for item in evidence_items],
            "timeline": [item.to_dict() for item in timeline],
            "risk_level": response.risk_level,
            "confidence": response.confidence,
            "similar_incidents": similar,
        }
        self.memory.save(stmt)
        return response

    def query(self, *args, **kwargs) -> CopilotResponse:
        return self.investigate(*args, **kwargs)

    def get_investigation(self, investigation_id: str) -> Dict[str, Any] | None:
        return self.memory.get(investigation_id)

    def list_investigations(self) -> List[Dict[str, Any]]:
        return self.memory.list()

    def submit_feedback(self, investigation_id: str, label: str, comment: str = "") -> Dict[str, Any]:
        return self.memory.append_feedback(investigation_id, label, comment)

    def simulate_action(self, action: str, target: str, tenant_id: str, analyst_id: str, role: str, permissions: Optional[List[str]] = None) -> Dict[str, Any]:
        result = self.guardrails.evaluate_action(action, target, tenant_id, analyst_id, role, permissions or [])
        if result["allowed"]:
            return {"status": "SIMULATED", "message": f"Action {action} is allowed and safe to simulate.", **result}
        return {"status": "REQUIRES_APPROVAL", "message": "Approval required before execution.", **result, "simulated_outcome": simulate_remediation(target)}


__all__ = ["AIInvestigationCopilot"]
