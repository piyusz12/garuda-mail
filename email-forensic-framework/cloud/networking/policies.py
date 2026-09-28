"""
Cloud Network Policy and Exposure Analysis.
Component 28: Analyzes security groups and identifies overly permissive exposure.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from .networks import SecurityGroup, SecurityGroupRule, RuleDirection


@dataclass
class SecurityGroupFinding:
    group_id: str
    group_name: str
    rule_id: str
    exposed_port: int
    port_description: str
    severity: str
    recommendation: str
    description: str = ""

    def __post_init__(self):
        if not self.description:
            self.description = f"Security group {self.group_name} exposes port {self.exposed_port} ({self.port_description}) unrestricted to internet."


class CloudNetworkPolicyEvaluator:
    """Evaluates security group rules for dangerous public exposures."""

    HIGH_RISK_PORTS = {
        22: "SSH Management",
        3389: "RDP Remote Desktop",
        5432: "PostgreSQL Database",
        3306: "MySQL Database",
        27017: "MongoDB Database",
        6379: "Redis Cache",
        2375: "Unauthenticated Docker Daemon",
        10250: "Kubelet API",
    }

    @classmethod
    def audit_security_group(cls, sg: SecurityGroup) -> List[Dict[str, Any]]:
        findings = []
        for r in sg.rules:
            if r.is_unrestricted_ingress():
                # Check for high-risk ports
                for port, desc in cls.HIGH_RISK_PORTS.items():
                    if r.from_port <= port <= r.to_port:
                        findings.append({
                            "group_id": sg.group_id,
                            "group_name": sg.group_name,
                            "rule_id": r.rule_id,
                            "exposed_port": port,
                            "port_description": desc,
                            "severity": "CRITICAL",
                            "description": f"Security group {sg.group_name} exposes {desc} (Port {port}) unrestricted to internet.",
                            "recommendation": f"Remove 0.0.0.0/0 ingress for {desc} (Port {port}). Restrict to internal CIDR or bastion.",
                        })
        return findings

    def evaluate_security_group(self, sg: SecurityGroup) -> List[SecurityGroupFinding]:
        raw_findings = self.audit_security_group(sg)
        return [
            SecurityGroupFinding(
                group_id=f["group_id"],
                group_name=f["group_name"],
                rule_id=f["rule_id"],
                exposed_port=f["exposed_port"],
                port_description=f["port_description"],
                severity=f["severity"],
                recommendation=f["recommendation"],
                description=f["description"],
            )
            for f in raw_findings
        ]
