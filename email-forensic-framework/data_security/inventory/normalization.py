"""
Data Asset Normalization and Canonical Data Entity Modeling.
Components 29.1, 29.5, 29.6: Normalizes tables, columns, objects, and streams into canonical DataAsset entities.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class DataAssetType(str, Enum):
    DATABASE = "DATABASE"
    TABLE = "TABLE"
    COLUMN = "COLUMN"
    OBJECT = "OBJECT"
    FILE = "FILE"
    BUCKET = "BUCKET"
    DATASET = "DATASET"
    STREAM = "STREAM"
    TOPIC = "TOPIC"
    QUEUE = "QUEUE"
    CACHE = "CACHE"
    LOG = "LOG"
    BACKUP = "BACKUP"
    SNAPSHOT = "SNAPSHOT"
    WAREHOUSE = "WAREHOUSE"
    DATA_LAKE = "DATA_LAKE"
    VECTOR_COLLECTION = "VECTOR_COLLECTION"


class ClassificationLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE = "SENSITIVE"
    RESTRICTED = "RESTRICTED"


@dataclass
class DataAsset:
    data_asset_id: str
    name: str
    asset_type: DataAssetType
    environment: str = "production"
    location: str = "us-east-1"
    storage_system: str = "PostgreSQL"
    classification: ClassificationLevel = ClassificationLevel.INTERNAL
    sensitivity_score: float = 10.0  # 0 to 100
    business_owner: str = "data-platform@garuda.enterprise"
    technical_owner: str = "db-admin@garuda.enterprise"
    security_owner: str = "secops@garuda.enterprise"
    data_steward: str = "steward-01@garuda.enterprise"
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    kms_key_id: Optional[str] = "KMS-KEY-PQC-01"
    tokenization_status: str = "RAW"  # RAW, TOKENIZED, PSEUDONYMIZED, HASHED, ENCRYPTED
    retention_days: int = 365
    is_publicly_exposed: bool = False
    record_count: int = 0
    size_bytes: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    parent_asset_id: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    schema_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_asset_id": self.data_asset_id,
            "name": self.name,
            "asset_type": self.asset_type.value if isinstance(self.asset_type, DataAssetType) else self.asset_type,
            "environment": self.environment,
            "location": self.location,
            "storage_system": self.storage_system,
            "classification": self.classification.value if isinstance(self.classification, ClassificationLevel) else self.classification,
            "sensitivity_score": round(self.sensitivity_score, 1),
            "business_owner": self.business_owner,
            "technical_owner": self.technical_owner,
            "security_owner": self.security_owner,
            "data_steward": self.data_steward,
            "encryption_at_rest": self.encryption_at_rest,
            "encryption_in_transit": self.encryption_in_transit,
            "kms_key_id": self.kms_key_id,
            "tokenization_status": self.tokenization_status,
            "retention_days": self.retention_days,
            "is_publicly_exposed": self.is_publicly_exposed,
            "record_count": self.record_count,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_accessed": self.last_accessed,
            "parent_asset_id": self.parent_asset_id,
            "tags": self.tags,
            "schema_metadata": self.schema_metadata,
        }


class DataNormalizer:
    """Normalizes heterogeneous data source descriptors into canonical DataAsset entities."""

    @classmethod
    def normalize_database_table(
        cls,
        table_name: str,
        database_name: str,
        columns: List[Dict[str, Any]],
        record_count: int = 10000,
        owner: str = "customer-platform",
    ) -> DataAsset:
        return DataAsset(
            data_asset_id=f"DATA-TBL-{abs(hash(f'{database_name}.{table_name}')) % 100000}",
            name=f"{database_name}.{table_name}",
            asset_type=DataAssetType.TABLE,
            storage_system="PostgreSQL-Aurora",
            business_owner=owner,
            record_count=record_count,
            schema_metadata={"columns": columns, "database": database_name, "table": table_name},
        )

    @classmethod
    def normalize_storage_object(
        cls,
        bucket_name: str,
        object_key: str,
        size_bytes: int = 500000,
        is_public: bool = False,
    ) -> DataAsset:
        return DataAsset(
            data_asset_id=f"DATA-OBJ-{abs(hash(f'{bucket_name}/{object_key}')) % 100000}",
            name=f"{bucket_name}/{object_key}",
            asset_type=DataAssetType.OBJECT,
            storage_system="S3",
            size_bytes=size_bytes,
            is_publicly_exposed=is_public,
            schema_metadata={"bucket": bucket_name, "key": object_key},
        )
