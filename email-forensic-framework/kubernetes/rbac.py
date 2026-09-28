"""
Kubernetes RBAC Privilege Analysis.
Component 17: Audits Roles, ClusterRoles, RoleBindings, and flags excessive or wildcard permissions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class RBACPolicyRule:
    api_groups: List[str]  # e.g., ["", "apps", "batch"]
    resources: List[str]   # e.g., ["pods", "secrets", "deployments", "*"]
    verbs: List[str]       # e.g., ["get", "list", "watch", "create", "*"]

    def is_wildcard_permission(self) -> bool:
        return "*" in self.resources or "*" in self.verbs


@dataclass
class K8sRoleBinding:
    binding_id: str
    name: str
    namespace: Optional[str]  # None for ClusterRoleBinding
    subject_kind: str         # ServiceAccount, User, Group
    subject_name: str
    role_name: str
    is_cluster_admin: bool = False
    rules: List[RBACPolicyRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "name": self.name,
            "namespace": self.namespace,
            "subject_kind": self.subject_kind,
            "subject_name": self.subject_name,
            "role_name": self.role_name,
            "is_cluster_admin": self.is_cluster_admin,
            "has_wildcard": any(r.is_wildcard_permission() for r in self.rules),
        }


@dataclass
class RBACFinding:
    binding_id: str
    subject: str
    severity: str
    risk: str
    description: str
    remediation: str
    title: str = ""

    def __post_init__(self):
        if not self.title:
            self.title = f"RBAC Risk: {self.risk} on {self.subject}"


class RBACAnalyzer:
    """Detects over-permissive service accounts and dangerous cluster-level role bindings."""

    @classmethod
    def audit_bindings(cls, bindings: List[K8sRoleBinding]) -> List[Dict[str, Any]]:
        findings = []
        for b in bindings:
            if b.is_cluster_admin and b.subject_kind == "ServiceAccount" and "system:" not in b.subject_name:
                findings.append({
                    "binding_id": b.binding_id,
                    "subject": f"{b.subject_kind}/{b.subject_name}",
                    "severity": "CRITICAL",
                    "risk": "CLUSTER_ADMIN_SERVICE_ACCOUNT",
                    "title": f"Excessive cluster-admin binding on {b.subject_name}",
                    "description": f"Service account '{b.subject_name}' is bound to cluster-admin privileges.",
                    "remediation": "Replace cluster-admin binding with a least-privilege namespaced Role.",
                })

            for rule in b.rules:
                if rule.is_wildcard_permission():
                    findings.append({
                        "binding_id": b.binding_id,
                        "subject": f"{b.subject_kind}/{b.subject_name}",
                        "severity": "HIGH",
                        "risk": "WILDCARD_RBAC_PERMISSION",
                        "title": f"Wildcard permission granted in role '{b.role_name}'",
                        "description": f"Role '{b.role_name}' grants wildcard ('*') access on {rule.resources}.",
                        "remediation": "Restrict verbs to exact required operations (e.g., get, list).",
                    })
        return findings

    def analyze_binding(self, binding: K8sRoleBinding) -> List[RBACFinding]:
        raw = self.audit_bindings([binding])
        return [
            RBACFinding(
                binding_id=f["binding_id"],
                subject=f["subject"],
                severity=f["severity"],
                risk=f["risk"],
                title=f["title"],
                description=f["description"],
                remediation=f["remediation"],
            )
            for f in raw
        ]
