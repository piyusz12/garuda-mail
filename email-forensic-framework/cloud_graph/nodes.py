"""
Cloud Security Graph Nodes and Entities.
Components 40, 41, 42: Models entities across Cloud, Kubernetes, Workload, Identity, and Data.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class CloudNodeType(str, Enum):
    USER = "USER"
    IAM_ROLE = "IAM_ROLE"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    K8S_CLUSTER = "K8S_CLUSTER"
    NAMESPACE = "NAMESPACE"
    WORKLOAD = "WORKLOAD"
    POD = "POD"
    CONTAINER = "CONTAINER"
    DATABASE = "DATABASE"
    STORAGE_BUCKET = "STORAGE_BUCKET"
    API_ENDPOINT = "API_ENDPOINT"
    KMS_KEY = "KMS_KEY"


@dataclass
class CloudNode:
    node_id: str
    node_type: CloudNodeType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value if isinstance(self.node_type, CloudNodeType) else self.node_type,
            "name": self.name,
            "properties": self.properties,
            "risk_score": self.risk_score,
        }
