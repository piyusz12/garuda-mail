"""
Kubernetes Cluster and Node Inventory.
Component 6 & 7: Models Kubernetes clusters, control planes, nodes, and cluster posture.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class ClusterPostureLevel(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL_RISK = "CRITICAL_RISK"


@dataclass
class K8sNode:
    node_id: str
    hostname: str
    cluster_id: str
    kubelet_version: str = "v1.30.2"
    os_image: str = "Ubuntu 24.04 LTS"
    container_runtime: str = "containerd://1.7.15"
    is_ready: bool = True
    is_control_plane: bool = False
    taints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "cluster_id": self.cluster_id,
            "kubelet_version": self.kubelet_version,
            "is_ready": self.is_ready,
            "is_control_plane": self.is_control_plane,
        }


@dataclass
class K8sCluster:
    cluster_id: str
    name: str
    provider: str  # EKS, GKE, AKS, SELF_HOSTED
    account_id: str
    kubernetes_version: str = "1.30"
    api_endpoint_public: bool = False
    nodes: Dict[str, K8sNode] = field(default_factory=dict)
    posture_level: ClusterPostureLevel = ClusterPostureLevel.HEALTHY
    audit_logging_enabled: bool = True
    network_policy_enforced: bool = True
    admission_webhook_active: bool = True
    created_at: float = field(default_factory=time.time)

    def evaluate_posture(self) -> ClusterPostureLevel:
        issues = 0
        if self.api_endpoint_public:
            issues += 2
        if not self.audit_logging_enabled:
            issues += 1
        if not self.network_policy_enforced:
            issues += 1
        if not self.admission_webhook_active:
            issues += 1

        if issues >= 2:
            self.posture_level = ClusterPostureLevel.CRITICAL_RISK
        elif issues == 1:
            self.posture_level = ClusterPostureLevel.DEGRADED
        else:
            self.posture_level = ClusterPostureLevel.HEALTHY
        return self.posture_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "name": self.name,
            "provider": self.provider,
            "account_id": self.account_id,
            "kubernetes_version": self.kubernetes_version,
            "api_endpoint_public": self.api_endpoint_public,
            "nodes_count": len(self.nodes),
            "posture_level": self.posture_level.value if isinstance(self.posture_level, ClusterPostureLevel) else self.posture_level,
            "audit_logging_enabled": self.audit_logging_enabled,
            "network_policy_enforced": self.network_policy_enforced,
            "admission_webhook_active": self.admission_webhook_active,
        }


class K8sClusterRepository:
    """Registry for enterprise Kubernetes clusters."""

    def __init__(self):
        self._clusters: Dict[str, K8sCluster] = {}
        self._load_defaults()

    def _load_defaults(self):
        c1 = K8sCluster(
            cluster_id="CLUSTER-PROD-01",
            name="garuda-prod-us-east-cluster",
            provider="EKS",
            account_id="ACC-AWS-PROD-01",
            kubernetes_version="1.30.2",
            api_endpoint_public=False,
            audit_logging_enabled=True,
            network_policy_enforced=True,
            admission_webhook_active=True,
        )
        c1.nodes["node-1"] = K8sNode("node-1", "ip-10-0-1-10.ec2.internal", c1.cluster_id, is_control_plane=False)
        c1.nodes["node-2"] = K8sNode("node-2", "ip-10-0-1-11.ec2.internal", c1.cluster_id, is_control_plane=False)

        c2 = K8sCluster(
            cluster_id="CLUSTER-DEV-01",
            name="garuda-dev-sandbox-cluster",
            provider="GKE",
            account_id="ACC-GCP-SEC-01",
            kubernetes_version="1.29.4",
            api_endpoint_public=True,  # Deliberate degraded finding
            audit_logging_enabled=True,
            network_policy_enforced=False,
            admission_webhook_active=False,
        )
        c2.evaluate_posture()

        self._clusters[c1.cluster_id] = c1
        self._clusters[c2.cluster_id] = c2

    def get(self, cluster_id: str) -> Optional[K8sCluster]:
        return self._clusters.get(cluster_id)

    def list_all(self) -> List[K8sCluster]:
        return list(self._clusters.values())

    def register(self, cluster: K8sCluster) -> None:
        self._clusters[cluster.cluster_id] = cluster
