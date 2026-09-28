"""
Cloud Resource Discovery and Inventory Modeling.
Component 2: Models VMs, clusters, buckets, databases, API gateways, load balancers, and security groups.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from cloud.inventory.accounts import CloudProvider, EnvironmentType
from identity.ingestion.services import ResourceClassification


class CloudResourceType(str, Enum):
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"
    STORAGE_BUCKET = "STORAGE_BUCKET"
    DATABASE = "DATABASE"
    LOAD_BALANCER = "LOAD_BALANCER"
    API_GATEWAY = "API_GATEWAY"
    SERVERLESS_FUNCTION = "SERVERLESS_FUNCTION"
    SECURITY_GROUP = "SECURITY_GROUP"
    IAM_ROLE = "IAM_ROLE"
    KMS_KEY = "KMS_KEY"


@dataclass
class CloudResource:
    resource_id: str
    name: str
    resource_type: CloudResourceType
    provider: CloudProvider
    account_id: str
    region: str
    environment: EnvironmentType = EnvironmentType.PRODUCTION
    classification: ResourceClassification = ResourceClassification.INTERNAL
    is_internet_facing: bool = False
    encryption_enabled: bool = True
    logging_enabled: bool = True
    is_publicly_accessible: Optional[bool] = None
    is_encrypted: Optional[bool] = None
    tags: Dict[str, str] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_discovered_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.is_publicly_accessible is not None:
            self.is_internet_facing = self.is_publicly_accessible
        else:
            self.is_publicly_accessible = self.is_internet_facing
        if self.is_encrypted is not None:
            self.encryption_enabled = self.is_encrypted
        else:
            self.is_encrypted = self.encryption_enabled

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "resource_type": self.resource_type.value if isinstance(self.resource_type, CloudResourceType) else self.resource_type,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "environment": self.environment.value if isinstance(self.environment, EnvironmentType) else self.environment,
            "classification": self.classification.value if isinstance(self.classification, ResourceClassification) else self.classification,
            "is_internet_facing": self.is_internet_facing,
            "encryption_enabled": self.encryption_enabled,
            "logging_enabled": self.logging_enabled,
            "tags": self.tags,
            "attributes": self.attributes,
            "last_discovered_at": self.last_discovered_at,
        }


class CloudResourceRepository:
    """Discovery registry for multi-cloud enterprise resources."""

    def __init__(self):
        self._resources: Dict[str, CloudResource] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            CloudResource(
                resource_id="RES-K8S-01",
                name="garuda-prod-eks-cluster",
                resource_type=CloudResourceType.KUBERNETES_CLUSTER,
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                environment=EnvironmentType.PRODUCTION,
                classification=ResourceClassification.CRITICAL,
                is_internet_facing=False,
                encryption_enabled=True,
                logging_enabled=True,
                attributes={"version": "1.30", "nodes_count": 8, "vpc_id": "vpc-0912fa8b"},
            ),
            CloudResource(
                resource_id="RES-BUCKET-EVIDENCE-01",
                name="garuda-immutable-forensic-evidence",
                resource_type=CloudResourceType.STORAGE_BUCKET,
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                environment=EnvironmentType.PRODUCTION,
                classification=ResourceClassification.CRITICAL,
                is_internet_facing=False,
                encryption_enabled=True,
                logging_enabled=True,
                attributes={"versioning": True, "object_lock": True, "kms_key_id": "KMS-KEY-PQC-01"},
            ),
            CloudResource(
                resource_id="RES-DB-POSTGRES-01",
                name="garuda-mail-state-aurora",
                resource_type=CloudResourceType.DATABASE,
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                environment=EnvironmentType.PRODUCTION,
                classification=ResourceClassification.CRITICAL,
                is_internet_facing=False,
                encryption_enabled=True,
                logging_enabled=True,
                attributes={"engine": "postgres-16", "multi_az": True, "storage_encrypted": True},
            ),
            CloudResource(
                resource_id="RES-LB-EDGE-01",
                name="garuda-edge-mail-ingress-nlb",
                resource_type=CloudResourceType.LOAD_BALANCER,
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                environment=EnvironmentType.PRODUCTION,
                classification=ResourceClassification.CRITICAL,
                is_internet_facing=True,
                encryption_enabled=True,
                logging_enabled=True,
                attributes={"scheme": "internet-facing", "ports": [25, 587, 465]},
            ),
            CloudResource(
                resource_id="RES-API-GW-01",
                name="garuda-soc-forensic-gateway",
                resource_type=CloudResourceType.API_GATEWAY,
                provider=CloudProvider.GCP,
                account_id="ACC-GCP-SEC-01",
                region="us-central1",
                environment=EnvironmentType.PRODUCTION,
                classification=ResourceClassification.SENSITIVE,
                is_internet_facing=False,
                encryption_enabled=True,
                logging_enabled=True,
                attributes={"protocol": "HTTPS", "mtls": True},
            ),
        ]
        for r in defaults:
            self._resources[r.resource_id] = r

    def get(self, resource_id: str) -> Optional[CloudResource]:
        return self._resources.get(resource_id)

    def list_all(self, resource_type: Optional[CloudResourceType] = None) -> List[CloudResource]:
        resources = list(self._resources.values())
        if resource_type:
            resources = [r for r in resources if r.resource_type == resource_type]
        return resources

    def register(self, resource: CloudResource) -> None:
        self._resources[resource.resource_id] = resource
