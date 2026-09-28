"""
Kubernetes Workload Inventory & Security Context.
Component 9: Models Deployments, Pods, StatefulSets, DaemonSets, and runtime containers.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class WorkloadType(str, Enum):
    DEPLOYMENT = "DEPLOYMENT"
    POD = "POD"
    STATEFULSET = "STATEFULSET"
    DAEMONSET = "DAEMONSET"
    JOB = "JOB"


@dataclass
class K8sWorkload:
    workload_id: str
    name: str
    workload_type: WorkloadType
    cluster_id: str
    namespace: str
    image_tag: str
    image_digest: str
    service_account: str = "default"
    service_identity_id: Optional[str] = None
    is_quarantined: bool = False
    is_privileged: bool = False
    read_only_root_filesystem: bool = True
    run_as_non_root: bool = True
    allow_privilege_escalation: bool = False
    risk_score: float = 15.0  # 0 to 100
    replica_count: int = 3
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "name": self.name,
            "workload_type": self.workload_type.value if isinstance(self.workload_type, WorkloadType) else self.workload_type,
            "cluster_id": self.cluster_id,
            "namespace": self.namespace,
            "image_tag": self.image_tag,
            "image_digest": self.image_digest,
            "service_account": self.service_account,
            "service_identity_id": self.service_identity_id,
            "is_quarantined": self.is_quarantined,
            "is_privileged": self.is_privileged,
            "read_only_root_filesystem": self.read_only_root_filesystem,
            "run_as_non_root": self.run_as_non_root,
            "allow_privilege_escalation": self.allow_privilege_escalation,
            "risk_score": round(self.risk_score, 1),
            "replica_count": self.replica_count,
        }


class K8sWorkloadRepository:
    """Registry of enterprise Kubernetes workloads."""

    def __init__(self):
        self._workloads: Dict[str, K8sWorkload] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            K8sWorkload(
                workload_id="WORKLOAD-991",
                name="mta-edge-relay",
                workload_type=WorkloadType.DEPLOYMENT,
                cluster_id="CLUSTER-PROD-01",
                namespace="email-ingress",
                image_tag="garuda/mta-edge:v2.4.1",
                image_digest="sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222",
                service_account="sa-mta-pipeline",
                service_identity_id="MTA-07",
                is_quarantined=False,
                is_privileged=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                risk_score=15.0,
                replica_count=4,
            ),
            K8sWorkload(
                workload_id="WORKLOAD-FORENSIC-01",
                name="forensic-investigation-api",
                workload_type=WorkloadType.DEPLOYMENT,
                cluster_id="CLUSTER-PROD-01",
                namespace="security-ops",
                image_tag="garuda/forensic-api:v3.1.0",
                image_digest="sha256:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b",
                service_account="sa-forensic-api",
                service_identity_id="FORENSIC-API",
                is_quarantined=False,
                is_privileged=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                risk_score=10.0,
                replica_count=2,
            ),
            K8sWorkload(
                workload_id="WORKLOAD-TEST-SUSPICIOUS",
                name="unapproved-crypto-collector",
                workload_type=WorkloadType.POD,
                cluster_id="CLUSTER-DEV-01",
                namespace="default",
                image_tag="unknown-registry/debug-tool:latest",
                image_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
                service_account="default",
                is_quarantined=False,
                is_privileged=True,  # Deliberate risk factor
                read_only_root_filesystem=False,
                run_as_non_root=False,
                risk_score=85.0,
                replica_count=1,
            ),
        ]
        for w in defaults:
            self._workloads[w.workload_id] = w

    def get(self, workload_id: str) -> Optional[K8sWorkload]:
        return self._workloads.get(workload_id)

    def list_all(self, namespace: Optional[str] = None) -> List[K8sWorkload]:
        w_list = list(self._workloads.values())
        if namespace:
            w_list = [w for w in w_list if w.namespace == namespace]
        return w_list

    def register(self, workload: K8sWorkload) -> None:
        self._workloads[workload.workload_id] = workload
