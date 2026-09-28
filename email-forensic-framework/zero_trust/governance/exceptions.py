"""
Policy Exception Management.
Component 96 & 97: Manages time-bounded exceptions with mandatory expiration dates and compensating controls.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


@dataclass
class PolicyException:
    exception_id: str
    policy_id: str
    subject_id: str
    resource_id: str
    reason: str
    owner_id: str
    approver_id: str
    valid_from: float
    expires_at: float
    compensating_controls: List[str] = field(default_factory=list)
    is_revoked: bool = False

    def is_currently_valid(self) -> bool:
        if self.is_revoked:
            return False
        now = time.time()
        return self.valid_from <= now <= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "policy_id": self.policy_id,
            "subject_id": self.subject_id,
            "resource_id": self.resource_id,
            "reason": self.reason,
            "owner_id": self.owner_id,
            "approver_id": self.approver_id,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "compensating_controls": self.compensating_controls,
            "is_valid": self.is_currently_valid(),
        }


class PolicyExceptionManager:
    """Tracks and enforces expiration of policy exceptions."""

    def __init__(self):
        self._exceptions: Dict[str, PolicyException] = {}

    def grant_exception(
        self,
        policy_id: str,
        subject_id: str,
        resource_id: str,
        reason: str,
        owner_id: str,
        approver_id: str,
        duration_days: int = 14,
        compensating_controls: Optional[List[str]] = None,
    ) -> PolicyException:
        now = time.time()
        exp_id = f"EXC-{uuid.uuid4().hex[:6].upper()}"
        exc = PolicyException(
            exception_id=exp_id,
            policy_id=policy_id,
            subject_id=subject_id,
            resource_id=resource_id,
            reason=reason,
            owner_id=owner_id,
            approver_id=approver_id,
            valid_from=now,
            expires_at=now + (duration_days * 86400),
            compensating_controls=compensating_controls or ["MANDATORY_SESSION_RECORDING"],
        )
        self._exceptions[exp_id] = exc
        return exc

    def revoke_exception(self, exception_id: str) -> PolicyException:
        exc = self._exceptions.get(exception_id)
        if not exc:
            raise KeyError(f"Exception {exception_id} not found.")
        exc.is_revoked = True
        return exc

    def has_valid_exception(self, subject_id: str, resource_id: str) -> bool:
        for exc in self._exceptions.values():
            if exc.subject_id == subject_id and exc.resource_id == resource_id:
                if exc.is_currently_valid():
                    return True
        return False

    def list_exceptions(self) -> List[PolicyException]:
        return list(self._exceptions.values())
