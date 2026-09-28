"""
Enterprise Data Source Connectors.
Component 29.2: Connectors for relational databases, object stores, warehouses, lakes, and event streams.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class DataSourceType(str, Enum):
    RELATIONAL_DB = "RELATIONAL_DB"
    NOSQL_DB = "NOSQL_DB"
    OBJECT_STORAGE = "OBJECT_STORAGE"
    DATA_WAREHOUSE = "DATA_WAREHOUSE"
    DATA_LAKE = "DATA_LAKE"
    STREAM_QUEUE = "STREAM_QUEUE"
    VECTOR_COLLECTION = "VECTOR_COLLECTION"


class ConnectionStatus(str, Enum):
    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"


@dataclass
class DataSourceConnector:
    connector_id: str
    name: str
    source_type: DataSourceType
    target_uri: str
    cloud_provider: str = "AWS"
    account_id: str = "ACC-AWS-PROD-01"
    region: str = "us-east-1"
    environment: str = "production"
    status: ConnectionStatus = ConnectionStatus.CONNECTED
    last_scanned_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "source_type": self.source_type.value if isinstance(self.source_type, DataSourceType) else self.source_type,
            "target_uri": self.target_uri,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "environment": self.environment,
            "status": self.status.value if isinstance(self.status, ConnectionStatus) else self.status,
            "last_scanned_at": self.last_scanned_at,
            "metadata": self.metadata,
        }
