"""
Scenario & Campaign Approval Workflows.
Tracks multi-tier validation requests, decisions, and audit trails.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class ScenarioApprovalRequest:
    request_id: str
    scenario_id: str
    blast_radius: str
    requester_id: str
    approver_id: Optional[str] = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    decision_reason: Optional[str] = None
    requested_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "scenario_id": self.scenario_id,
            "blast_radius": self.blast_radius,
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "status": self.status.value if isinstance(self.status, ApprovalStatus) else self.status,
            "decision_reason": self.decision_reason,
            "requested_at": self.requested_at,
            "decided_at": self.decided_at,
        }


class ApprovalWorkflowManager:
    """Manages approvals for emulation scenarios and validation campaigns."""

    def __init__(self):
        self._requests: Dict[str, ScenarioApprovalRequest] = {}

    def submit_request(self, scenario_id: str, blast_radius: str, requester_id: str) -> ScenarioApprovalRequest:
        req_id = f"REQ-VAL-{uuid.uuid4().hex[:6].upper()}"
        req = ScenarioApprovalRequest(
            request_id=req_id,
            scenario_id=scenario_id,
            blast_radius=blast_radius,
            requester_id=requester_id,
        )
        self._requests[req_id] = req
        return req

    def get_request(self, request_id: str) -> Optional[ScenarioApprovalRequest]:
        return self._requests.get(request_id)

    def list_requests(self, status: Optional[ApprovalStatus] = None) -> List[ScenarioApprovalRequest]:
        reqs = list(self._requests.values())
        if status:
            reqs = [r for r in reqs if r.status == status]
        return reqs

    def submit_decision(self, request_id: str, approver_id: str, decision: str, reason: str) -> ScenarioApprovalRequest:
        req = self._requests.get(request_id)
        if not req:
            raise ValueError(f"Approval request {request_id} not found.")

        req.approver_id = approver_id
        req.decision_reason = reason
        req.decided_at = time.time()
        req.status = ApprovalStatus.APPROVED if decision.upper() == "APPROVED" else ApprovalStatus.REJECTED
        return req
