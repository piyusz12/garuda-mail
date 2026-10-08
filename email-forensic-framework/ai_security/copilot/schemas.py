from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class InvestigationIntent(str, Enum):
    INVESTIGATE = "INVESTIGATE"
    EXPLAIN = "EXPLAIN"
    HUNT = "HUNT"
    SUMMARIZE = "SUMMARIZE"
    COMPARE = "COMPARE"
    RECOMMEND = "RECOMMEND"
    SIMULATE = "SIMULATE"
    RESPOND = "RESPOND"
    REPORT = "REPORT"
    SEARCH = "SEARCH"


@dataclass
class CopilotQuery:
    query: str
    tenant_id: str = "TENANT-001"
    analyst_id: str = "ANALYST-01"
    role: str = "SOC_ANALYST"
    permissions: List[str] = field(default_factory=lambda: ["read:incidents", "read:alerts"])
    entity_id: Optional[str] = None
    time_range: str = "90d"
    severity: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "tenant_id": self.tenant_id,
            "analyst_id": self.analyst_id,
            "role": self.role,
            "permissions": self.permissions,
            "entity_id": self.entity_id,
            "time_range": self.time_range,
            "severity": self.severity,
        }


@dataclass
class Evidence:
    evidence_id: str
    category: str
    description: str
    confidence: float
    source: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "category": self.category,
            "description": self.description,
            "confidence": self.confidence,
            "source": self.source,
            "references": self.references,
        }


@dataclass
class Recommendation:
    recommendation_id: str
    case_id: str
    target: str
    recommended_action: str
    reason: List[str]
    risk_class: str = "R2_CONTAINMENT"
    requires_approval: bool = True
    rollback_available: bool = True
    security_gain: str = "HIGH"
    operational_impact: str = "LOW"
    confidence: float = 0.9

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "case_id": self.case_id,
            "target": self.target,
            "recommended_action": self.recommended_action,
            "reason": self.reason,
            "risk_class": self.risk_class,
            "requires_approval": self.requires_approval,
            "rollback_available": self.rollback_available,
            "security_gain": self.security_gain,
            "operational_impact": self.operational_impact,
            "confidence": self.confidence,
        }


@dataclass
class InvestigationTimeline:
    timestamp: str
    description: str
    category: str = "EVENT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "description": self.description,
            "category": self.category,
        }


@dataclass
class ToolCall:
    tool_name: str
    args: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "args": self.args,
            "result": self.result,
        }


@dataclass
class CopilotResponse:
    investigation_id: str
    intent: InvestigationIntent
    answer: str
    risk_level: str
    confidence: float
    entities: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    timeline: List[InvestigationTimeline] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    requires_approval: bool = False
    citations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "intent": self.intent.value if isinstance(self.intent, InvestigationIntent) else str(self.intent),
            "answer": self.answer,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "entities": self.entities,
            "evidence": self.evidence,
            "timeline": [item.to_dict() for item in self.timeline],
            "recommendations": self.recommendations,
            "actions": self.actions,
            "requires_approval": self.requires_approval,
            "citations": self.citations,
        }


@dataclass
class Investigation:
    investigation_id: str
    query: str
    tenant_id: str
    analyst_id: str
    intent: InvestigationIntent
    entity_id: str
    status: str = "OPEN"
    evidence: List[Evidence] = field(default_factory=list)
    timeline: List[InvestigationTimeline] = field(default_factory=list)
    recommendations: List[Recommendation] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    result: Optional[str] = None
    confidence: float = 0.0
    risk_level: str = "MEDIUM"
    citations: List[str] = field(default_factory=list)
    created_at: str = "2026-01-01T00:00:00Z"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "query": self.query,
            "tenant_id": self.tenant_id,
            "analyst_id": self.analyst_id,
            "intent": self.intent.value,
            "entity_id": self.entity_id,
            "status": self.status,
            "evidence": [item.to_dict() for item in self.evidence],
            "timeline": [item.to_dict() for item in self.timeline],
            "recommendations": [item.to_dict() for item in self.recommendations],
            "actions": self.actions,
            "result": self.result,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "citations": self.citations,
            "created_at": self.created_at,
        }


@dataclass
class Citation:
    source: str
    reference: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "reference": self.reference,
            "description": self.description,
        }
