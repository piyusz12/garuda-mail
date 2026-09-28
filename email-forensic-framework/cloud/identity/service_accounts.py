"""
Cloud Service Account Management.
Component 5: Tracks managed and unmanaged service principals across cloud accounts.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from cloud.inventory.accounts import CloudProvider


@dataclass
class CloudServiceAccount:
    service_account_id: str
    name: str
    principal_email: str
    provider: CloudProvider
    account_id: str
    associated_roles: List[str] = field(default_factory=list)
    keys_count: int = 1
    has_active_keys: bool = True
    last_authenticated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_account_id": self.service_account_id,
            "name": self.name,
            "principal_email": self.principal_email,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "account_id": self.account_id,
            "associated_roles": self.associated_roles,
            "keys_count": self.keys_count,
            "has_active_keys": self.has_active_keys,
            "last_authenticated_at": self.last_authenticated_at,
        }


class ServiceAccountRepository:
    """Registry for cloud service principals."""

    def __init__(self):
        self._accounts: Dict[str, CloudServiceAccount] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            CloudServiceAccount(
                service_account_id="SA-MTA-RELAY-01",
                name="sa-mta-pipeline",
                principal_email="sa-mta-pipeline@garuda-prod.iam.gserviceaccount.com",
                provider=CloudProvider.GCP,
                account_id="ACC-GCP-SEC-01",
                associated_roles=["ROLE-MTA-WORKLOAD-01"],
                keys_count=1,
            ),
            CloudServiceAccount(
                service_account_id="SA-EKS-NODE-01",
                name="eks-node-instance-principal",
                principal_email="eks-nodes@aws.internal",
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                associated_roles=["ROLE-K8S-ADMIN-01"],
                keys_count=0,
            ),
        ]
        for sa in defaults:
            self._accounts[sa.service_account_id] = sa

    def get(self, sa_id: str) -> Optional[CloudServiceAccount]:
        return self._accounts.get(sa_id)

    def list_all(self) -> List[CloudServiceAccount]:
        return list(self._accounts.values())

    def register(self, sa: CloudServiceAccount) -> None:
        self._accounts[sa.service_account_id] = sa
