"""
Access Simulation & "What-If" Analysis.
Component 42 & 85: Evaluates policy outcomes under simulated environment perturbations (e.g. device posture degradation).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import copy

from zero_trust.decision.context import AccessRequestContext
from zero_trust.decision.engine import PolicyDecisionPoint, AccessDecisionRecord


@dataclass
class AccessSimulationResult:
    scenario_description: str
    original_decision: str
    simulated_decision: str
    decision_changed: bool
    impact_level: str  # NONE, RESTRICTED, BLOCKED, ELEVATED
    reasons: List[str]
    context_diff: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_description": self.scenario_description,
            "original_decision": self.original_decision,
            "simulated_decision": self.simulated_decision,
            "decision_changed": self.decision_changed,
            "impact_level": self.impact_level,
            "reasons": self.reasons,
            "context_diff": self.context_diff,
        }


class AccessSimulator:
    """Simulates policy evaluations under hypothetical changes without touching production state."""

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pdp = pdp

    def simulate_perturbation(
        self,
        base_context: AccessRequestContext,
        attribute_overrides: Dict[str, Any],
        scenario_description: str = "Hypothetical context perturbation",
    ) -> AccessSimulationResult:
        # 1. Base evaluation
        base_eval = self.pdp.evaluate_access(base_context, use_cache=False)

        # 2. Mutated context
        mutated_ctx = copy.deepcopy(base_context)
        for attr, val in attribute_overrides.items():
            if attr == "device_managed":
                mutated_ctx.device_managed = val
            elif attr == "device_posture":
                mutated_ctx.device_posture = val
            elif attr == "session_risk":
                mutated_ctx.session_risk = val
            elif attr == "resource_classification":
                mutated_ctx.resource_classification = val
            elif attr == "action":
                mutated_ctx.action = val

        # 3. Simulated evaluation
        sim_eval = self.pdp.evaluate_access(mutated_ctx, use_cache=False)

        changed = base_eval.decision != sim_eval.decision
        impact = "NONE"
        if changed:
            if sim_eval.decision == "DENY":
                impact = "BLOCKED"
            elif sim_eval.decision == "STEP_UP":
                impact = "ELEVATED"
            elif sim_eval.decision == "RESTRICT":
                impact = "RESTRICTED"

        return AccessSimulationResult(
            scenario_description=scenario_description,
            original_decision=base_eval.decision,
            simulated_decision=sim_eval.decision,
            decision_changed=changed,
            impact_level=impact,
            reasons=sim_eval.reasons,
            context_diff=attribute_overrides,
        )
