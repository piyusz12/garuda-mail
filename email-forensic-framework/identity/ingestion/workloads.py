"""
Workload Identity Ingestion.
Represents containerized microservices, serverless functions, and SPIFFE-attested workloads.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class WorkloadIdentity:
    workload_id: str
    service_id: str
    spiffe_id: str  # e.g., spiffe://enterprise.org/ns/mail-core/sa/mta-relay
    cluster_name: str
    namespace: str
    pod_or_container_id: str
    runtime_type: str  # k8s, docker, container_d, serverless
    certificate_id: Optional[str]
    is_attested: bool = True
    attestation_method: str = "X509_SVID"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "service_id": self.service_id,
            "spiffe_id": self.spiffe_id,
            "cluster_name": self.cluster_name,
            "namespace": self.namespace,
            "pod_or_container_id": self.pod_or_container_id,
            "runtime_type": self.runtime_type,
            "certificate_id": self.certificate_id,
            "is_attested": self.is_attested,
            "attestation_method": self.attestation_method,
        }


class WorkloadIdentityRepository:
    """Registry of microservice workload identities."""

    def __init__(self):
        self._workloads: Dict[str, WorkloadIdentity] = {}
        self._load_defaults()

    def _load_defaults(self):
        w1 = WorkloadIdentity(
            workload_id="WORKLOAD-MTA-RELAY-01",
            service_id="MTA-07",
            spiffe_id="spiffe://enterprise.org/ns/mail-core/sa/mta-relay",
            cluster_name="k8s-prod-us-east-1",
            namespace="mail-core",
            pod_or_container_id="pod-mta-7c89f5bc-x8k2p",
            runtime_type="k8s",
            certificate_id="CERT-SVID-MTA-01",
            is_attested=True,
        )
        w2 = WorkloadIdentity(
            workload_id="WORKLOAD-FORENSIC-API-01",
            service_id="FORENSIC-API",
            spiffe_id="spiffe://enterprise.org/ns/soc-ops/sa/forensic-api",
            cluster_name="k8s-sec-ops-01",
            namespace="soc-ops",
            pod_or_container_id="pod-forensic-api-44bf2-11a",
            runtime_type="k8s",
            certificate_id="CERT-SVID-API-01",
            is_attested=True,
        )
        self._workloads[w1.workload_id] = w1
        self._workloads[w2.workload_id] = w2

    def get(self, workload_id: str) -> Optional[WorkloadIdentity]:
        return self._workloads.get(workload_id)

    def list_all(self) -> List[WorkloadIdentity]:
        return list(self._workloads.values())

    def register(self, workload: WorkloadIdentity) -> None:
        self._workloads[workload.workload_id] = workload
