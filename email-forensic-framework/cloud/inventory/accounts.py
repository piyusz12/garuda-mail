"""
Cloud Account Inventory and Multi-Cloud Tenant Management.
Component 1: Tracks accounts, subscriptions, projects, regions, and environments.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    PRIVATE_CLOUD = "PRIVATE_CLOUD"
    HYBRID = "HYBRID"


class EnvironmentType(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    CYBER_RANGE = "CYBER_RANGE"


@dataclass
class CloudAccount:
    account_id: str
    account_name: str
    provider: CloudProvider
    environment: EnvironmentType
    regions: List[str] = field(default_factory=lambda: ["us-east-1"])
    owner_email: str = "cloud-admin@garuda.enterprise"
    owner: Optional[str] = None
    is_active: bool = True
    compliance_score: float = 95.0
    discovered_resources_count: int = 0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.owner and not self.owner_email:
            self.owner_email = self.owner
        elif self.owner:
            self.owner_email = self.owner

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "account_name": self.account_name,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "environment": self.environment.value if isinstance(self.environment, EnvironmentType) else self.environment,
            "regions": self.regions,
            "owner_email": self.owner_email,
            "is_active": self.is_active,
            "compliance_score": round(self.compliance_score, 1),
            "discovered_resources_count": self.discovered_resources_count,
            "created_at": self.created_at,
        }


class CloudAccountRepository:
    """Registry and state tracker for enterprise cloud accounts."""

    def __init__(self):
        self._accounts: Dict[str, CloudAccount] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            CloudAccount(
                account_id="ACC-AWS-PROD-01",
                account_name="Garuda Production AWS Primary",
                provider=CloudProvider.AWS,
                environment=EnvironmentType.PRODUCTION,
                regions=["us-east-1", "us-west-2"],
                owner_email="infra-lead@garuda.enterprise",
                compliance_score=94.5,
                discovered_resources_count=142,
            ),
            CloudAccount(
                account_id="ACC-GCP-SEC-01",
                account_name="Garuda Security Operations GCP",
                provider=CloudProvider.GCP,
                environment=EnvironmentType.PRODUCTION,
                regions=["us-central1"],
                owner_email="secops@garuda.enterprise",
                compliance_score=98.0,
                discovered_resources_count=48,
            ),
            CloudAccount(
                account_id="ACC-AZURE-HYBRID-01",
                account_name="Garuda Corporate Directory Azure",
                provider=CloudProvider.AZURE,
                environment=EnvironmentType.PRODUCTION,
                regions=["eastus"],
                owner_email="identity-eng@garuda.enterprise",
                compliance_score=91.0,
                discovered_resources_count=35,
            ),
        ]
        for a in defaults:
            self._accounts[a.account_id] = a

    def get(self, account_id: str) -> Optional[CloudAccount]:
        return self._accounts.get(account_id)

    def list_all(self) -> List[CloudAccount]:
        return list(self._accounts.values())

    def register(self, account: CloudAccount) -> None:
        self._accounts[account.account_id] = account
