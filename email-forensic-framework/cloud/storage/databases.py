"""
Cloud Database Security Modeling.
Component 34: Tracks managed databases, encryption, access controls, and network boundaries.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from cloud.inventory.accounts import CloudProvider


@dataclass
class CloudDatabase:
    database_id: str
    name: str
    engine: str  # PostgreSQL, Aurora, CloudSQL, CosmosDB
    provider: CloudProvider
    account_id: str
    is_public: bool = False
    encrypted: bool = True
    multi_az: bool = True
    backup_retention_days: int = 35
    iam_auth_enabled: bool = True
    kms_key_id: Optional[str] = "KMS-KEY-PQC-01"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "database_id": self.database_id,
            "name": self.name,
            "engine": self.engine,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "account_id": self.account_id,
            "is_public": self.is_public,
            "encrypted": self.encrypted,
            "multi_az": self.multi_az,
            "backup_retention_days": self.backup_retention_days,
            "iam_auth_enabled": self.iam_auth_enabled,
        }


class DatabaseRepository:
    """Registry for cloud databases."""

    def __init__(self):
        self._databases: Dict[str, CloudDatabase] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            CloudDatabase(
                database_id="DB-MAIL-STATE-01",
                name="garuda-mail-state-aurora",
                engine="Aurora-PostgreSQL-16",
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                is_public=False,
                encrypted=True,
                multi_az=True,
                backup_retention_days=35,
                iam_auth_enabled=True,
            ),
            CloudDatabase(
                database_id="DB-LEGACY-ANALYTICS",
                name="garuda-dev-analytics-pg",
                engine="PostgreSQL-14",
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                is_public=True,  # Deliberate finding
                encrypted=False, # Deliberate finding
                multi_az=False,
                backup_retention_days=7,
                iam_auth_enabled=False,
            ),
        ]
        for db in defaults:
            self._databases[db.database_id] = db

    def get(self, database_id: str) -> Optional[CloudDatabase]:
        return self._databases.get(database_id)

    def list_all(self) -> List[CloudDatabase]:
        return list(self._databases.values())

    def register(self, db: CloudDatabase) -> None:
        self._databases[db.database_id] = db
