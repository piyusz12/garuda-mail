"""
Cloud Storage Bucket Security Modeling.
Component 35: Tracks object stores, shares, encryption, and public exposure.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from cloud.inventory.accounts import CloudProvider


@dataclass
class StorageBucket:
    bucket_id: str
    bucket_name: str
    provider: CloudProvider
    account_id: str
    region: str
    is_public: bool = False
    encryption_enabled: bool = True
    kms_key_id: Optional[str] = "KMS-KEY-PQC-01"
    versioning_enabled: bool = True
    object_lock_enabled: bool = True
    logging_enabled: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_id": self.bucket_id,
            "bucket_name": self.bucket_name,
            "provider": self.provider.value if isinstance(self.provider, CloudProvider) else self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "is_public": self.is_public,
            "encryption_enabled": self.encryption_enabled,
            "kms_key_id": self.kms_key_id,
            "versioning_enabled": self.versioning_enabled,
            "object_lock_enabled": self.object_lock_enabled,
            "logging_enabled": self.logging_enabled,
        }


class StorageBucketRepository:
    """Registry for enterprise cloud storage buckets."""

    def __init__(self):
        self._buckets: Dict[str, StorageBucket] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            StorageBucket(
                bucket_id="BUCKET-EVIDENCE-01",
                bucket_name="garuda-immutable-forensic-evidence",
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                is_public=False,
                encryption_enabled=True,
                kms_key_id="KMS-KEY-PQC-01",
                versioning_enabled=True,
                object_lock_enabled=True,
                logging_enabled=True,
            ),
            StorageBucket(
                bucket_id="BUCKET-PUBLIC-ASSETS",
                bucket_name="garuda-portal-static-assets",
                provider=CloudProvider.AWS,
                account_id="ACC-AWS-PROD-01",
                region="us-east-1",
                is_public=True,
                encryption_enabled=True,
                versioning_enabled=False,
                object_lock_enabled=False,
                logging_enabled=True,
            ),
        ]
        for b in defaults:
            self._buckets[b.bucket_id] = b

    def get(self, bucket_id: str) -> Optional[StorageBucket]:
        return self._buckets.get(bucket_id)

    def list_all(self) -> List[StorageBucket]:
        return list(self._buckets.values())

    def register(self, bucket: StorageBucket) -> None:
        self._buckets[bucket.bucket_id] = bucket
