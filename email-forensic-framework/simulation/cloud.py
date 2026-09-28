"""
Cloud Infrastructure Digital Twin Simulator.
Component 57: Simulates cloud topology changes, multi-cloud expansions, and security group alterations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from cloud.inventory.resources import CloudResource, CloudResourceType
from cloud.networking.networks import SecurityGroup, SecurityGroupRule


@dataclass
class CloudSimulationScenario:
    scenario_id: str
    description: str
    target_resource_id: str
    proposed_security_group_rules: List[Dict[str, Any]] = field(default_factory=list)
    proposed_network_changes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudSimulationOutcome:
    scenario_id: str
    target_resource_id: str
    safe_to_apply: bool
    risk_level: str
    newly_exposed_ports: List[int]
    unintended_reachability_created: bool
    affected_resources: List[str]
    recommendation: str


class CloudSimulator:
    """Simulates the blast radius and exposure impact of cloud configuration changes."""

    def simulate_sg_change(
        self,
        resource: CloudResource,
        current_sg: SecurityGroup,
        proposed_rules: List[SecurityGroupRule],
    ) -> CloudSimulationOutcome:
        """Evaluate the effect of adding or modifying security group rules."""
        high_risk_ports = {22, 3389, 23, 21, 5432, 3306, 9200, 27017}
        newly_exposed: List[int] = []
        unintended_reach = False

        for rule in proposed_rules:
            if rule.source_cidr in ["0.0.0.0/0", "::/0"] and rule.is_ingress:
                if rule.to_port in high_risk_ports or rule.from_port in high_risk_ports:
                    newly_exposed.append(rule.from_port)
                    unintended_reach = True

        safe = not unintended_reach
        risk_level = "CRITICAL" if newly_exposed else "LOW"
        recommendation = (
            f"REJECT: Proposed rules expose sensitive ports {newly_exposed} to 0.0.0.0/0 without bastion or VPN."
            if not safe
            else "APPROVE: Proposed rules adhere to cloud security posture."
        )

        return CloudSimulationOutcome(
            scenario_id=f"SIM-SG-{resource.resource_id}",
            target_resource_id=resource.resource_id,
            safe_to_apply=safe,
            risk_level=risk_level,
            newly_exposed_ports=newly_exposed,
            unintended_reachability_created=unintended_reach,
            affected_resources=[resource.resource_id],
            recommendation=recommendation,
        )
