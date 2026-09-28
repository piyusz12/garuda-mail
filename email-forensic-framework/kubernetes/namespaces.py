"""
Kubernetes Namespace Security and Boundary Modeling.
Component 8: Treats namespaces as security boundaries and controls cross-namespace access.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class K8sNamespace:
    namespace_id: str
    name: str
    cluster_id: str
    environment: str = "production"
    is_system_namespace: bool = False
    default_deny_network_policy: bool = True
    labels: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "namespace_id": self.namespace_id,
            "name": self.name,
            "cluster_id": self.cluster_id,
            "environment": self.environment,
            "is_system_namespace": self.is_system_namespace,
            "default_deny_network_policy": self.default_deny_network_policy,
            "labels": self.labels,
        }


class NamespaceSecurityBoundary:
    """Enforces cross-namespace communication barriers."""

    # Explicit allowed cross-namespace channels
    ALLOWED_CROSS_NAMESPACE_FLOWS = {
        ("security-ops", "email-ingress"): True,
        ("security-ops", "mail-core"): True,
        ("email-ingress", "mail-core"): True,
    }

    @classmethod
    def can_communicate_cross_namespace(cls, src_namespace: str, dst_namespace: str) -> bool:
        if src_namespace == dst_namespace:
            return True
        return cls.ALLOWED_CROSS_NAMESPACE_FLOWS.get((src_namespace, dst_namespace), False)
