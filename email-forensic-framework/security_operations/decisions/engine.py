"""
Phase 25 — Security Decision & Operational Explainability Engine
Evaluates dynamic risk against policy gates to determine next operational action,
providing explainable rationales, evidence pointers, and uncertainty flags.
"""

from typing import Dict, List, Optional, Any
from .risk import DynamicRiskScorer, UncertaintyModel
from .policies import PolicyRegistry, DecisionPolicy


class DecisionEngine:
    """Evaluates contextual risk and outputs policy-governed decisions with explainability."""

    def __init__(self, policy_registry: Optional[PolicyRegistry] = None):
        self.risk_scorer = DynamicRiskScorer()
        self.policy_registry = policy_registry or PolicyRegistry()

    def evaluate(self, context: Dict[str, Any], tenant_id: str = "default") -> Dict[str, Any]:
        """
        Calculates dynamic risk, applies policy rules, and returns an explainable decision.
        Possible decision values:
            NO_ACTION, MONITOR, INVESTIGATE, ESCALATE, REQUEST_APPROVAL, EXECUTE_AUTOMATICALLY
        """
        risk_result = self.risk_scorer.score(context)
        risk_score = risk_result["risk_score"]
        factors = risk_result["factors"]
        uncertainty = risk_result["uncertainty_model"]

        policy: DecisionPolicy = self.policy_registry.get_policy(tenant_id)
        criticality = str(context.get("criticality", "MEDIUM")).upper()
        in_maint = bool(context.get("in_maintenance_window", False))
        is_expected = bool(context.get("is_expected_change", False))

        reasons: List[str] = []
        evidence_pointers: List[str] = []
        recommended_action = "MONITOR_TELEMETRY"

        # Check for uncertainty override
        uncertainty_obj = UncertaintyModel(**uncertainty)
        is_uncertain, low_dims = uncertainty_obj.is_uncertain(threshold=0.65)
        if is_uncertain:
            reasons.append(f"Uncertainty model detected low confidence in: {', '.join(low_dims)}.")

        # Check maintenance suppression
        if is_expected:
            decision = "MONITOR"
            reasons.append("Observed telemetry aligns with an approved ITSM change ticket inside a maintenance window.")
            evidence_pointers.append("APPROVED_MAINTENANCE_WINDOW")
            return {
                "decision": decision,
                "risk_score": max(5.0, risk_score * 0.2),  # Suppressed risk
                "factors": factors,
                "uncertainty_model": uncertainty,
                "recommended_action": "LOG_EXPECTED_CHANGE",
                "reasons": reasons,
                "evidence_pointers": evidence_pointers,
                "autonomy_level_applied": policy.autonomy_level,
            }

        # Select recommended action based on event type
        event_types = context.get("event_types", [])
        if any("cert" in str(et).lower() for et in event_types):
            recommended_action = "VERIFY_AND_ROTATE_CERTIFICATE"
            evidence_pointers.append("CERTIFICATE_ANOMALY_RECORD")
        elif any("ja4" in str(et).lower() for et in event_types):
            recommended_action = "QUARANTINE_JA4_PROFILE"
            evidence_pointers.append("RARE_JA4_SIGNATURE")
        elif any("tls" in str(et).lower() or "downgrade" in str(et).lower() for et in event_types):
            recommended_action = "DISABLE_LEGACY_TLS_CANARY"
            evidence_pointers.append("TLS_DOWNGRADE_SESSIONS")
        else:
            recommended_action = "ISOLATE_COMPROMISED_SESSION"
            evidence_pointers.append("SECURITY_ANOMALY_BURST")

        # Evaluate decision gates
        if is_uncertain and risk_score >= policy.investigate_threshold:
            decision = "ESCALATE"
            reasons.append("High uncertainty requires senior security analyst review before remediation.")
        elif risk_score < policy.monitor_threshold:
            decision = "NO_ACTION" if risk_score < 10 else "MONITOR"
            reasons.append(f"Risk score {risk_score} is below operational investigation threshold ({policy.monitor_threshold}).")
        elif risk_score < policy.investigate_threshold:
            decision = "INVESTIGATE"
            reasons.append(f"Moderate risk score {risk_score} warrants automated context gathering.")
        elif risk_score < policy.response_threshold:
            decision = "ESCALATE"
            reasons.append(f"Elevated risk score {risk_score} requires analyst escalation and containment review.")
        else:
            # High risk >= 80
            reasons.append(f"High risk score {risk_score} requires rapid remediation.")
            if criticality == "CRITICAL" and policy.require_approval_for_critical_assets:
                decision = "REQUEST_APPROVAL"
                reasons.append("Target asset criticality is CRITICAL; mandatory human approval gate enforced.")
            elif policy.autonomy_level >= 3:
                decision = "EXECUTE_AUTOMATICALLY"
                reasons.append(f"Autonomy Level {policy.autonomy_level} permits automated safe remediation execution.")
            else:
                decision = "REQUEST_APPROVAL"
                reasons.append(f"Policy Autonomy Level {policy.autonomy_level} requires analyst approval before action execution.")

        return {
            "decision": decision,
            "risk_score": risk_score,
            "factors": factors,
            "uncertainty_model": uncertainty,
            "recommended_action": recommended_action,
            "reasons": reasons,
            "evidence_pointers": evidence_pointers,
            "autonomy_level_applied": policy.autonomy_level,
        }
