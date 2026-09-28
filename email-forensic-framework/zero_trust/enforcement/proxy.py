"""
Policy Enforcement Point (PEP) & Network Proxy Adapter.
Intercepts connection requests, queries the PDP, enforces ALLOW/DENY/STEP-UP, and dispatches telemetry.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from zero_trust.decision.context import AccessRequestContext
from zero_trust.decision.engine import PolicyDecisionPoint, AccessDecisionRecord


class EnforcementAction(str, Enum):
    FORWARD = "FORWARD"
    BLOCK = "BLOCK"
    CHALLENGE_STEPUP = "CHALLENGE_STEPUP"
    THROTTLE = "THROTTLE"


@dataclass
class EnforcementResult:
    action: EnforcementAction
    status_code: int
    decision_record: AccessDecisionRecord
    headers_injected: Dict[str, str] = field(default_factory=dict)
    response_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value if isinstance(self.action, EnforcementAction) else self.action,
            "status_code": self.status_code,
            "decision": self.decision_record.to_dict(),
            "headers_injected": self.headers_injected,
            "response_message": self.response_message,
        }


class PolicyEnforcementPoint:
    """Enforces PDP decisions at the ingress proxy / gateway boundary."""

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def enforce(self, context: AccessRequestContext) -> EnforcementResult:
        dec_record = self.pdp.evaluate_access(context)

        if dec_record.decision == "ALLOW":
            return EnforcementResult(
                action=EnforcementAction.FORWARD,
                status_code=200,
                decision_record=dec_record,
                headers_injected={
                    "X-ZeroTrust-Identity": context.subject_id,
                    "X-ZeroTrust-Device": context.device_id,
                    "X-ZeroTrust-Policy": dec_record.matched_policy_id or "default",
                },
                response_message="Access authorized by Zero Trust PDP.",
            )
        elif dec_record.decision == "STEP_UP":
            return EnforcementResult(
                action=EnforcementAction.CHALLENGE_STEPUP,
                status_code=401,
                decision_record=dec_record,
                headers_injected={"WWW-Authenticate": "WebAuthn Step-Up Required"},
                response_message="Step-Up MFA Authentication Required.",
            )
        elif dec_record.decision == "RESTRICT":
            return EnforcementResult(
                action=EnforcementAction.FORWARD,
                status_code=200,
                decision_record=dec_record,
                headers_injected={"X-ZeroTrust-Restriction": "ReadOnly"},
                response_message="Access permitted under restricted read-only posture.",
            )
        else:
            return EnforcementResult(
                action=EnforcementAction.BLOCK,
                status_code=403,
                decision_record=dec_record,
                response_message=f"Access Denied: {'; '.join(dec_record.reasons)}",
            )
