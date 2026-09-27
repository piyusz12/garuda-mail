"""
Phase 25 — Multi-Tier Approval Gates & Four-Eyes Verification
Enforces human authorization boundaries across Low, Medium, High, and Critical risk actions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import hashlib
import time
import uuid


class ApprovalTier(str, Enum):
    LOW_IMPACT = "LOW_IMPACT"          # 0 approvals required (automatic)
    MEDIUM_IMPACT = "MEDIUM_IMPACT"    # 1 Analyst approval
    HIGH_IMPACT = "HIGH_IMPACT"        # 1 Senior Analyst / SecLead approval
    CRITICAL = "CRITICAL"              # Multi-person / Four-Eyes (2 independent approvals)


@dataclass
class ApprovalDecision:
    decision_id: str
    approver_id: str
    role: str
    decision: str  # APPROVED, REJECTED
    reason: str
    timestamp: float
    action_hash: str


@dataclass
class ApprovalRequest:
    request_id: str
    action_id: str
    case_id: str
    tier: ApprovalTier
    required_approvals: int
    action_hash: str
    details: Dict[str, Any] = field(default_factory=dict)
    decisions: List[ApprovalDecision] = field(default_factory=list)
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    created_at: float = field(default_factory=time.time)

    def is_fully_approved(self) -> bool:
        approved_count = len([d for d in self.decisions if d.decision == "APPROVED"])
        return approved_count >= self.required_approvals

    def is_rejected(self) -> bool:
        return any(d.decision == "REJECTED" for d in self.decisions)


class ApprovalWorkflow:
    """Manages creation, review, and verification of human approval gates."""

    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}

    def create_request(
        self,
        action_id: str,
        case_id: str,
        tier: ApprovalTier,
        action_payload: Dict[str, Any],
    ) -> ApprovalRequest:
        req_count = 0
        if tier == ApprovalTier.LOW_IMPACT:
            req_count = 0
        elif tier == ApprovalTier.MEDIUM_IMPACT:
            req_count = 1
        elif tier == ApprovalTier.HIGH_IMPACT:
            req_count = 1
        elif tier == ApprovalTier.CRITICAL:
            req_count = 2

        action_hash = hashlib.sha256(str(sorted(action_payload.items())).encode("utf-8")).hexdigest()
        req_id = f"APP-{uuid.uuid4().hex[:8].upper()}"

        req = ApprovalRequest(
            request_id=req_id,
            action_id=action_id,
            case_id=case_id,
            tier=tier,
            required_approvals=req_count,
            action_hash=action_hash,
            details=action_payload,
            status="APPROVED" if req_count == 0 else "PENDING",
        )
        self._requests[req_id] = req
        return req

    def submit_decision(
        self,
        request_id: str,
        approver_id: str,
        role: str,
        decision: str,
        reason: str,
    ) -> ApprovalRequest:
        req = self._requests.get(request_id)
        if not req:
            raise KeyError(f"Approval request '{request_id}' not found.")

        # Prevent duplicate approval by same actor for Four-Eyes compliance
        if any(d.approver_id == approver_id for d in req.decisions):
            raise ValueError(f"Approver '{approver_id}' has already voted on request '{request_id}'.")

        dec = ApprovalDecision(
            decision_id=f"DEC-{uuid.uuid4().hex[:6].upper()}",
            approver_id=approver_id,
            role=role,
            decision=decision.upper(),
            reason=reason,
            timestamp=time.time(),
            action_hash=req.action_hash,
        )
        req.decisions.append(dec)

        if dec.decision == "REJECTED":
            req.status = "REJECTED"
        elif req.is_fully_approved():
            req.status = "APPROVED"

        return req

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(request_id)

    def list_requests(self) -> List[ApprovalRequest]:
        return list(self._requests.values())
