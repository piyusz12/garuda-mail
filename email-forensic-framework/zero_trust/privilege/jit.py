"""
Just-In-Time (JIT) Access Management.
Replaces standing administrative privileges with temporary, audited elevations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class JITStatus(str, Enum):
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class JITRequest:
    request_id: str
    identity_id: str
    role_requested: str  # e.g. MTA_ADMIN, SOC_ADMIN
    target_resource: str
    justification: str
    duration_minutes: int
    status: JITStatus = JITStatus.REQUESTED
    approver_id: Optional[str] = None
    approved_at: Optional[float] = None
    activated_at: Optional[float] = None
    expires_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)

    def is_currently_valid(self) -> bool:
        if self.status != JITStatus.ACTIVE:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "identity_id": self.identity_id,
            "role_requested": self.role_requested,
            "target_resource": self.target_resource,
            "justification": self.justification,
            "duration_minutes": self.duration_minutes,
            "status": self.status.value if isinstance(self.status, JITStatus) else self.status,
            "approver_id": self.approver_id,
            "expires_at": self.expires_at,
            "is_valid": self.is_currently_valid(),
        }


class JITAccessManager:
    """Manages creation, approval, activation, and expiration of JIT sessions."""

    def __init__(self):
        self._requests: Dict[str, JITRequest] = {}

    def request_access(
        self,
        identity_id: str,
        role_requested: str,
        target_resource: str,
        justification: str,
        duration_minutes: int = 30,
    ) -> JITRequest:
        req_id = f"JIT-{uuid.uuid4().hex[:6].upper()}"
        req = JITRequest(
            request_id=req_id,
            identity_id=identity_id,
            role_requested=role_requested,
            target_resource=target_resource,
            justification=justification,
            duration_minutes=duration_minutes,
        )
        self._requests[req_id] = req
        return req

    def approve_and_activate(self, request_id: str, approver_id: str) -> JITRequest:
        req = self._requests.get(request_id)
        if not req:
            raise KeyError(f"JIT request {request_id} not found.")

        now = time.time()
        req.approver_id = approver_id
        req.approved_at = now
        req.activated_at = now
        req.expires_at = now + (req.duration_minutes * 60)
        req.status = JITStatus.ACTIVE
        return req

    def revoke_access(self, request_id: str) -> JITRequest:
        req = self._requests.get(request_id)
        if not req:
            raise KeyError(f"JIT request {request_id} not found.")
        req.status = JITStatus.REVOKED
        return req

    def list_requests(self, identity_id: Optional[str] = None) -> List[JITRequest]:
        reqs = list(self._requests.values())
        if identity_id:
            reqs = [r for r in reqs if r.identity_id == identity_id]
        return reqs
