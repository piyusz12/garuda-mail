"""
Kubernetes NetworkPolicy Modeling and Evaluation.
Component 28: Ingress and Egress NetworkPolicy enforcement within and across namespaces.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import time


class NetworkPolicyType(str, Enum):
    INGRESS = "INGRESS"
    EGRESS = "EGRESS"
    BOTH = "BOTH"


@dataclass
class NetworkPolicyRule:
    ports: List[int] = field(default_factory=list)  # e.g., [25, 587]
    cidr_blocks: List[str] = field(default_factory=list)
    allowed_namespaces: List[str] = field(default_factory=list)
    allowed_pod_labels: Dict[str, str] = field(default_factory=dict)
    allowed_sources: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.allowed_sources and not self.cidr_blocks:
            self.cidr_blocks = list(self.allowed_sources)
        if self.allowed_destinations and not self.cidr_blocks:
            self.cidr_blocks = list(self.allowed_destinations)


@dataclass
class K8sNetworkPolicy:
    policy_id: str
    name: str
    namespace: str
    pod_selector: Dict[str, str]  # e.g. {"app": "mta-edge"}
    policy_types: List[NetworkPolicyType] = field(default_factory=lambda: [NetworkPolicyType.INGRESS, NetworkPolicyType.EGRESS])
    ingress_rules: List[NetworkPolicyRule] = field(default_factory=list)
    egress_rules: List[NetworkPolicyRule] = field(default_factory=list)
    is_default_deny: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "namespace": self.namespace,
            "pod_selector": self.pod_selector,
            "policy_types": [p.value for p in self.policy_types],
            "ingress_rules_count": len(self.ingress_rules),
            "egress_rules_count": len(self.egress_rules),
            "is_default_deny": self.is_default_deny,
        }


class NetworkPolicyEvaluator:
    """Evaluates whether ingress or egress flows are permitted under active NetworkPolicies."""

    def __init__(self, policies: Optional[List[K8sNetworkPolicy]] = None):
        self._policies: Dict[str, K8sNetworkPolicy] = {}
        if policies:
            for p in policies:
                self._policies[p.policy_id] = p
        else:
            self._load_defaults()

    def register_policy(self, policy: K8sNetworkPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def check_flow(
        self,
        namespace: str,
        source_pod_labels: Dict[str, str],
        destination_ip: str,
        destination_port: int,
        is_egress: bool = True,
    ) -> bool:
        import ipaddress
        for p in self._policies.values():
            if p.namespace == namespace and all(source_pod_labels.get(k) == v for k, v in p.pod_selector.items()):
                rules = p.egress_rules if is_egress else p.ingress_rules
                if not rules:
                    return False
                for r in rules:
                    port_match = not r.ports or destination_port in r.ports
                    cidr_match = True
                    if r.cidr_blocks:
                        try:
                            ip = ipaddress.ip_address(destination_ip)
                            cidr_match = any(ip in ipaddress.ip_network(cb) for cb in r.cidr_blocks)
                        except Exception:
                            cidr_match = False
                    if port_match and cidr_match:
                        return True
                return False
        return True

    def _load_defaults(self):
        # Default policy: allow ingress on port 25/587 for MTA in email-ingress namespace
        np_mta = K8sNetworkPolicy(
            policy_id="NP-MTA-INGRESS-01",
            name="allow-mta-mail-traffic",
            namespace="email-ingress",
            pod_selector={"app": "mta-edge"},
            policy_types=[NetworkPolicyType.INGRESS, NetworkPolicyType.EGRESS],
            ingress_rules=[
                NetworkPolicyRule(ports=[25, 587, 465], allowed_namespaces=["security-ops", "email-ingress"])
            ],
            egress_rules=[
                NetworkPolicyRule(ports=[25, 443, 9000], allowed_namespaces=["mail-core", "forensic-lake"])
            ],
        )
        self._policies[np_mta.policy_id] = np_mta

    def is_flow_allowed(
        self,
        src_namespace: str,
        dst_namespace: str,
        dst_port: int,
        pod_labels: Dict[str, str],
        direction: str = "INGRESS",
    ) -> bool:
        # Check policies applying to dst_namespace
        matching_policies = [p for p in self._policies.values() if p.namespace == dst_namespace]
        if not matching_policies:
            # If no NetworkPolicy is defined in destination namespace, traffic is allowed by default k8s behavior
            return True

        for p in matching_policies:
            # Check if policy selector matches pod
            if all(pod_labels.get(k) == v for k, v in p.pod_selector.items()):
                if p.is_default_deny:
                    return False

                rules = p.ingress_rules if direction == "INGRESS" else p.egress_rules
                for rule in rules:
                    port_matches = not rule.ports or dst_port in rule.ports
                    ns_matches = not rule.allowed_namespaces or src_namespace in rule.allowed_namespaces
                    if port_matches and ns_matches:
                        return True
                return False  # Policy selected this pod but flow didn't match rules

        return True
