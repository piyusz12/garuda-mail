"""
Policy Decision Explainer.
Generates human-understandable explanations for ALLOW, DENY, and STEP-UP decisions.
"""
from typing import Dict, List, Optional, Any
from .engine import AccessDecisionRecord


class PolicyDecisionExplainer:
    """Generates structured explanations for SOC analysts and users."""

    @staticmethod
    def explain(record: AccessDecisionRecord) -> Dict[str, Any]:
        d = record.decision

        if d == "ALLOW":
            summary = f"Access permitted to {record.resource_id} under policy '{record.matched_policy_id}'."
        elif d == "DENY":
            if record.risk_factors:
                summary = f"Access denied to {record.resource_id} due to security posture constraints: {'; '.join(record.risk_factors)}."
            else:
                summary = f"Access denied to {record.resource_id}: No matching authorization policy."
        elif d == "STEP_UP":
            summary = f"Step-up authentication required for access to {record.resource_id} due to elevated session risk or resource sensitivity."
        elif d == "RESTRICT":
            summary = f"Access granted in restricted/read-only mode to {record.resource_id}."
        else:
            summary = f"Access decision: {d}"

        return {
            "decision_id": record.decision_id,
            "decision": record.decision,
            "summary": summary,
            "subject": record.subject_id,
            "device": record.device_id,
            "resource": record.resource_id,
            "action": record.action,
            "policy": record.matched_policy_id,
            "reasons": record.reasons,
            "risk_factors": record.risk_factors,
            "context": record.context_snapshot,
        }
