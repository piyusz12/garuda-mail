"""
Cloud & Kubernetes Policy Simulation Engine.
Component 56: Simulates impact of NetworkPolicy, admission controls, and IAM rules before production deployment.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any


@dataclass
class PolicySimulationResult:
    simulation_id: str
    policy_name: str
    target_scope: str
    allowed_before: List[str]
    allowed_after: List[str]
    new_denials: List[str]
    new_permissions: List[str]
    affected_workloads: List[str]
    affected_services: List[str]
    verdict: str  # "SAFE", "WARNING", "BREAKING_CHANGE"
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "policy_name": self.policy_name,
            "target_scope": self.target_scope,
            "allowed_before": self.allowed_before,
            "allowed_after": self.allowed_after,
            "new_denials": self.new_denials,
            "new_permissions": self.new_permissions,
            "affected_workloads": self.affected_workloads,
            "affected_services": self.affected_services,
            "verdict": self.verdict,
            "summary": self.summary,
        }


class CloudPolicySimulator:
    """Pre-evaluates policy changes against active workload communication graphs."""

    def simulate_network_policy_change(
        self,
        policy_name: str,
        namespace: str,
        current_allowed_flows: List[str],
        proposed_allowed_flows: List[str],
        active_workloads: List[str],
    ) -> PolicySimulationResult:
        cur_set = set(current_allowed_flows)
        prop_set = set(proposed_allowed_flows)

        new_permissions = sorted(list(prop_set - cur_set))
        new_denials = sorted(list(cur_set - prop_set))

        # Check if critical telemetry or health check flows are accidentally cut
        breaking_denials = [d for d in new_denials if "healthz" in d or "telemetry" in d or "dns" in d]

        if breaking_denials:
            verdict = "BREAKING_CHANGE"
            summary = f"CRITICAL: Proposed policy would deny required infrastructure flows: {breaking_denials}"
        elif new_denials:
            verdict = "WARNING"
            summary = f"Proposed policy restricts {len(new_denials)} flows. Ensure dependent applications are prepared."
        else:
            verdict = "SAFE"
            summary = "Policy simulation completed with zero unintended breakages."

        return PolicySimulationResult(
            simulation_id=f"SIM-POL-{abs(hash(policy_name)) % 100000}",
            policy_name=policy_name,
            target_scope=f"namespace/{namespace}",
            allowed_before=sorted(list(cur_set)),
            allowed_after=sorted(list(prop_set)),
            new_denials=new_denials,
            new_permissions=new_permissions,
            affected_workloads=active_workloads,
            affected_services=[f"svc-{w.lower()}" for w in active_workloads],
            verdict=verdict,
            summary=summary,
        )
