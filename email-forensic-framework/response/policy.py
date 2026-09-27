"""
Phase 24 — Response Policy Engine & Policy-as-Code (Components 9, 40)
Externalized policy evaluator that inspects proposed actions against compliance, maintenance windows,
blast radius limits, and multi-signature approval rules.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from response.actions import ResponseAction, ActionType
from response.risk import ActionRiskClass


@dataclass
class PolicyEvaluationResult:
    compliant: bool
    required_approvals: int
    requires_four_eyes: bool
    requires_simulation: bool
    requires_rollback_plan: bool
    allowed_execution: bool
    violations: List[str] = field(default_factory=list)
    applied_rules: List[str] = field(default_factory=list)


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    condition: Callable[[ResponseAction, Dict[str, Any]], bool]
    enforce_approvals: int = 1
    enforce_four_eyes: bool = False
    enforce_simulation: bool = False
    deny_action: bool = False
    violation_message: str = ""


class ResponsePolicyEngine:
    """Evaluates Response Actions and Plans against organization policy constraints."""

    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._load_default_policies()

    def _load_default_policies(self):
        # 1. Critical asset protection policy: R4 or Network Isolation requires 2 approvals
        self.rules.append(
            PolicyRule(
                rule_id="POL-CRIT-ASSET-01",
                description="Actions on CRITICAL assets or R4 risk class require Four-Eyes approval (approval_count >= 2).",
                condition=lambda act, ctx: ctx.get("asset_criticality") == "CRITICAL" or act.risk_class == ActionRiskClass.R4,
                enforce_approvals=2,
                enforce_four_eyes=True,
                enforce_simulation=True,
                violation_message="Critical asset / R4 action requires minimum of 2 authorized human approvals."
            )
        )

        # 2. Blast radius threshold policy: blast_radius > 0.25 mandates digital twin pre-simulation
        self.rules.append(
            PolicyRule(
                rule_id="POL-BLAST-SIM-02",
                description="Blast radius exceeding 25% requires prior digital twin compatibility simulation.",
                condition=lambda act, ctx: ctx.get("blast_radius", 0.0) > 0.25,
                enforce_approvals=1,
                enforce_simulation=True,
                violation_message="Blast radius > 25% mandates pre-simulation before authorization."
            )
        )

        # 3. Certificate Revocation Governance: requires PKI officer approval
        self.rules.append(
            PolicyRule(
                rule_id="POL-PKI-REVOKE-03",
                description="Certificate revocation actions must be approved by certificate owner or PKI administrator.",
                condition=lambda act, ctx: act.action_type == ActionType.CERTIFICATE and "REVOKE" in act.forward_command.upper(),
                enforce_approvals=2,
                enforce_four_eyes=True,
                enforce_simulation=True,
                violation_message="Certificate revocation requires PKI officer multi-signature signoff."
            )
        )

        # 4. Rollback requirement for all mutable service impacts (R2, R3, R4)
        self.rules.append(
            PolicyRule(
                rule_id="POL-ROLLBACK-REQ-04",
                description="All mutating service actions (R2+) must provide valid rollback commands.",
                condition=lambda act, ctx: act.risk_class in [ActionRiskClass.R2, ActionRiskClass.R3, ActionRiskClass.R4] and not act.rollback_command,
                deny_action=True,
                violation_message="Non-reversible mutating action rejected: rollback command is mandatory."
            )
        )

    def evaluate_action(self, action: ResponseAction, context: Optional[Dict[str, Any]] = None) -> PolicyEvaluationResult:
        ctx = context or {}
        applied = []
        violations = []
        req_approvals = 0
        four_eyes = False
        simulation_req = False
        denied = False

        # Default baselines from action risk class
        if action.risk_class == ActionRiskClass.R3:
            req_approvals = max(req_approvals, 1)
            simulation_req = True
        elif action.risk_class == ActionRiskClass.R4:
            req_approvals = max(req_approvals, 2)
            four_eyes = True
            simulation_req = True

        for rule in self.rules:
            try:
                if rule.condition(action, ctx):
                    applied.append(rule.rule_id)
                    req_approvals = max(req_approvals, rule.enforce_approvals)
                    if rule.enforce_four_eyes:
                        four_eyes = True
                    if rule.enforce_simulation:
                        simulation_req = True
                    if rule.deny_action:
                        denied = True
                        violations.append(rule.violation_message)
            except Exception as e:
                violations.append(f"Policy rule {rule.rule_id} evaluation error: {str(e)}")

        return PolicyEvaluationResult(
            compliant=len(violations) == 0 and not denied,
            required_approvals=req_approvals,
            requires_four_eyes=four_eyes,
            requires_simulation=simulation_req,
            requires_rollback_plan=action.risk_class in [ActionRiskClass.R2, ActionRiskClass.R3, ActionRiskClass.R4],
            allowed_execution=len(violations) == 0 and not denied,
            violations=violations,
            applied_rules=applied
        )
