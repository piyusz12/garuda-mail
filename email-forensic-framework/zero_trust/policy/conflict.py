"""
Policy Conflict Detection and Rule Precedence Analyzer.
Identifies overlapping policies with conflicting effects (e.g. ALLOW vs DENY) and enforces strict precedence.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from .parser import ZeroTrustPolicy, PolicyEffect


@dataclass
class PolicyConflict:
    conflict_id: str
    policy_a_id: str
    policy_b_id: str
    overlapping_services: List[str]
    overlapping_actions: List[str]
    effect_a: str
    effect_b: str
    resolution_rule: str
    severity: str = "MEDIUM"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "policy_a_id": self.policy_a_id,
            "policy_b_id": self.policy_b_id,
            "overlapping_services": self.overlapping_services,
            "overlapping_actions": self.overlapping_actions,
            "effect_a": self.effect_a,
            "effect_b": self.effect_b,
            "resolution_rule": self.resolution_rule,
            "severity": self.severity,
        }


class PolicyConflictDetector:
    """Analyzes policy repositories to find overlaps and logical conflicts."""

    @staticmethod
    def detect_conflicts(policies: List[ZeroTrustPolicy]) -> List[PolicyConflict]:
        conflicts = []
        n = len(policies)

        for i in range(n):
            for j in range(i + 1, n):
                p1 = policies[i]
                p2 = policies[j]

                # If effects differ (e.g. ALLOW vs DENY or STEP_UP)
                if p1.effect != p2.effect:
                    # Check service overlap
                    services_overlap = (
                        "*" in p1.target_services
                        or "*" in p2.target_services
                        or any(s in p2.target_services for s in p1.target_services)
                    )

                    # Check action overlap
                    actions_overlap = (
                        "*" in p1.target_actions
                        or "*" in p2.target_actions
                        or any(a in p2.target_actions for a in p1.target_actions)
                    )

                    if services_overlap and actions_overlap:
                        # Conflict exists! Explicit Deny or Priority resolves it
                        res = "Priority order (lower priority int wins); Deny overrides Allow if priorities match"
                        conflicts.append(PolicyConflict(
                            conflict_id=f"CONF-{p1.policy_id}-{p2.policy_id}",
                            policy_a_id=p1.policy_id,
                            policy_b_id=p2.policy_id,
                            overlapping_services=list(set(p1.target_services).intersection(set(p2.target_services))) or ["*"],
                            overlapping_actions=list(set(p1.target_actions).intersection(set(p2.target_actions))) or ["*"],
                            effect_a=p1.effect.value,
                            effect_b=p2.effect.value,
                            resolution_rule=res,
                            severity="HIGH" if ("DENY" in (p1.effect.value, p2.effect.value) and "ALLOW" in (p1.effect.value, p2.effect.value)) else "MEDIUM",
                        ))

        return conflicts
