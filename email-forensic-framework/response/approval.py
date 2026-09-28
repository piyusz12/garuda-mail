"""
Phase 24 — Approval Engine & Four-Eyes Cryptographic Verification (Components 7, 8)
Governs single and multi-signature authorization for response plans and actions.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid

from response.actions import ResponseAction


class ApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class SignatureRecord:
    signature_id: str
    approver_id: str
    approver_role: str
    decision: ApprovalDecision
    reason: str
    timestamp: float
    action_hash_at_approval: str


@dataclass
class ApprovalRequest:
    request_id: str
    incident_id: str
    action_id: str
    action_name: str
    expected_action_hash: str
    required_approvals: int
    requires_four_eyes: bool
    state: ApprovalState = ApprovalState.PENDING
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)  # 1 hour
    signatures: List[SignatureRecord] = field(default_factory=list)
    rejection_reason: Optional[str] = None

    def is_fully_approved(self) -> bool:
        if self.state != ApprovalState.APPROVED:
            return False
        valid_approvals = [s for s in self.signatures if s.decision == ApprovalDecision.APPROVED and s.action_hash_at_approval == self.expected_action_hash]
        if self.requires_four_eyes:
            unique_approvers = {s.approver_id for s in valid_approvals}
            return len(unique_approvers) >= max(2, self.required_approvals)
        return len(valid_approvals) >= self.required_approvals

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApprovalEngine:
    """Manages approval lifecycles, four-eyes enforcement, and tamper-detection via cryptographic action hashing."""

    def __init__(self):
        self.requests: Dict[str, ApprovalRequest] = {}

    def create_request(
        self,
        incident_id: str,
        action: ResponseAction,
        required_approvals: int = 1,
        requires_four_eyes: bool = False
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            request_id=f"APPR-{uuid.uuid4().hex[:6].upper()}",
            incident_id=incident_id,
            action_id=action.action_id,
            action_name=action.name,
            expected_action_hash=action.compute_action_hash(),
            required_approvals=required_approvals,
            requires_four_eyes=requires_four_eyes
        )
        self.requests[req.request_id] = req
        return req

    def submit_decision(
        self,
        request_id: str,
        approver_id: str,
        approver_role: str,
        decision: ApprovalDecision,
        reason: str,
        action: ResponseAction
    ) -> ApprovalRequest:
        req = self.requests.get(request_id)
        if not req:
            raise KeyError(f"Approval request {request_id} not found")

        if req.state != ApprovalState.PENDING:
            raise ValueError(f"Approval request {request_id} is already in state {req.state.value}")

        current_hash = action.compute_action_hash()
        if current_hash != req.expected_action_hash:
            raise ValueError("Integrity failure: Action payload has changed since approval request was created!")

        # Prevent duplicate approval by same person
        if any(s.approver_id == approver_id for s in req.signatures):
            raise ValueError(f"Approver {approver_id} has already signed this request.")

        sig = SignatureRecord(
            signature_id=f"SIG-{uuid.uuid4().hex[:6].upper()}",
            approver_id=approver_id,
            approver_role=approver_role,
            decision=decision,
            reason=reason,
            timestamp=time.time(),
            action_hash_at_approval=current_hash
        )
        req.signatures.append(sig)

        if decision == ApprovalDecision.REJECTED:
            req.state = ApprovalState.REJECTED
            req.rejection_reason = reason
        else:
            # Check if threshold reached
            approvals_count = len([s for s in req.signatures if s.decision == ApprovalDecision.APPROVED])
            if req.requires_four_eyes:
                unique_approvers = {s.approver_id for s in req.signatures if s.decision == ApprovalDecision.APPROVED}
                if len(unique_approvers) >= max(2, req.required_approvals):
                    req.state = ApprovalState.APPROVED
            elif approvals_count >= req.required_approvals:
                req.state = ApprovalState.APPROVED

        return req
