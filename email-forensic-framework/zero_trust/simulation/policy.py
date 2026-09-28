"""
Policy Regression Testing & Comparative Analysis.
Component 43 & 44: Replays test suites against existing vs updated policies to detect unintended access regressions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import copy

from zero_trust.policy.parser import ZeroTrustPolicy
from zero_trust.decision.context import AccessRequestContext
from zero_trust.decision.engine import PolicyDecisionPoint


@dataclass
class PolicyRegressionReport:
    total_requests_tested: int
    unaltered_decisions_count: int
    newly_denied_count: int
    newly_allowed_count: int
    stepup_changes_count: int
    is_regression_free: bool
    regressed_requests: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests_tested": self.total_requests_tested,
            "unaltered_decisions_count": self.unaltered_decisions_count,
            "newly_denied_count": self.newly_denied_count,
            "newly_allowed_count": self.newly_allowed_count,
            "stepup_changes_count": self.stepup_changes_count,
            "is_regression_free": self.is_regression_free,
            "regressed_requests": self.regressed_requests,
        }


class PolicyRegressionTester:
    """Evaluates policy changes for unintended side-effects on legitimate requests."""

    @staticmethod
    def test_policy_change(
        baseline_policies: List[ZeroTrustPolicy],
        candidate_policies: List[ZeroTrustPolicy],
        test_requests: List[AccessRequestContext],
    ) -> PolicyRegressionReport:
        pdp_base = PolicyDecisionPoint()
        pdp_base._policies = {p.policy_id: p for p in baseline_policies}
        pdp_base._recompile()

        pdp_cand = PolicyDecisionPoint()
        pdp_cand._policies = {p.policy_id: p for p in candidate_policies}
        pdp_cand._recompile()

        unaltered = 0
        newly_denied = 0
        newly_allowed = 0
        stepup_changes = 0
        regressed = []

        for req in test_requests:
            d_base = pdp_base.evaluate_access(req, use_cache=False)
            d_cand = pdp_cand.evaluate_access(req, use_cache=False)

            if d_base.decision == d_cand.decision:
                unaltered += 1
            else:
                diff_entry = {
                    "subject": req.subject_id,
                    "resource": req.resource_id,
                    "action": req.action,
                    "baseline_decision": d_base.decision,
                    "candidate_decision": d_cand.decision,
                    "reasons": d_cand.reasons,
                }
                regressed.append(diff_entry)

                if d_base.decision == "ALLOW" and d_cand.decision == "DENY":
                    newly_denied += 1
                elif d_base.decision == "DENY" and d_cand.decision == "ALLOW":
                    newly_allowed += 1
                elif "STEP_UP" in (d_base.decision, d_cand.decision):
                    stepup_changes += 1

        is_clean = (newly_denied == 0)

        return PolicyRegressionReport(
            total_requests_tested=len(test_requests),
            unaltered_decisions_count=unaltered,
            newly_denied_count=newly_denied,
            newly_allowed_count=newly_allowed,
            stepup_changes_count=stepup_changes,
            is_regression_free=is_clean,
            regressed_requests=regressed,
        )
