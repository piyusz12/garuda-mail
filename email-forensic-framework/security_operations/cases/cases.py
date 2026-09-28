"""
Phase 25 — Operational Case Management
Defines Case entities, lifecycle states, evidence linkages, and tenant isolation.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class CaseStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    ASSESSED = "ASSESSED"
    AWAITING_DECISION = "AWAITING_DECISION"
    RESPONDING = "RESPONDING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    DUPLICATE = "DUPLICATE"
    ESCALATED = "ESCALATED"
    SUSPENDED = "SUSPENDED"
    REOPENED = "REOPENED"


class CasePriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class CaseTimelineEvent:
    event_id: str
    timestamp: float
    iso_time: str
    stage: str
    description: str
    actor: str
    hash: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    status: CaseStatus = CaseStatus.NEW
    priority: CasePriority = CasePriority.MEDIUM
    asset_id: str = "UNKNOWN-ASSET"
    tenant_id: str = "default"
    cluster_id: Optional[str] = None
    alert_ids: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    uncertainty_model: Dict[str, float] = field(default_factory=dict)
    playbook_id: Optional[str] = None
    recommended_action: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    action_ids: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    owner: str = "security_automation"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None
    sla_breached: bool = False
    reopened_from: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def transition_to(self, new_status: CaseStatus, actor: str = "orchestrator", reason: str = ""):
        self.status = new_status
        self.updated_at = time.time()
        if new_status in (CaseStatus.RESOLVED, CaseStatus.CLOSED):
            self.closed_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["priority"] = self.priority.value
        return data


class CaseManager:
    """Manages operational cases and multi-tenant case repository."""

    def __init__(self):
        self._cases: Dict[str, Case] = {}

    def create_case(
        self,
        title: str,
        description: str,
        asset_id: str,
        priority: CasePriority = CasePriority.MEDIUM,
        tenant_id: str = "default",
        cluster_id: Optional[str] = None,
        alert_ids: Optional[List[str]] = None,
        case_id: Optional[str] = None,
    ) -> Case:
        cid = case_id or f"CASE-{uuid.uuid4().hex[:6].upper()}"
        case = Case(
            case_id=cid,
            title=title,
            description=description,
            asset_id=asset_id,
            priority=priority,
            tenant_id=tenant_id,
            cluster_id=cluster_id,
            alert_ids=alert_ids or [],
        )
        self._cases[cid] = case
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        return self._cases.get(case_id)

    def list_cases(self, tenant_id: Optional[str] = None, status: Optional[CaseStatus] = None) -> List[Case]:
        cases = list(self._cases.values())
        if tenant_id:
            cases = [c for c in cases if c.tenant_id == tenant_id]
        if status:
            cases = [c for c in cases if c.status == status]
        return sorted(cases, key=lambda c: c.created_at, reverse=True)

    def clear(self):
        self._cases.clear()
