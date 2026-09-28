"""
Data Movement and Flow Telemetry Monitor.
Components 29.11 & 29.25: Captures database reads, exports, S3 copies, API transfers, and stream events.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid

from data_security.inventory.normalization import ClassificationLevel


class DataFlowChannel(str, Enum):
    API_HTTP = "API_HTTP"
    DATABASE_EXPORT = "DATABASE_EXPORT"
    S3_OBJECT_COPY = "S3_OBJECT_COPY"
    STREAM_PUBLISH = "STREAM_PUBLISH"
    EMAIL_DELIVERY = "EMAIL_DELIVERY"
    BULK_DOWNLOAD = "BULK_DOWNLOAD"


@dataclass
class DataMovementEvent:
    event_id: str
    source_asset_id: str
    destination_id: str
    identity_id: str
    workload_id: str
    bytes_transferred: int
    record_count: int
    classification: ClassificationLevel
    channel: DataFlowChannel
    is_external_destination: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source_asset_id": self.source_asset_id,
            "destination_id": self.destination_id,
            "identity_id": self.identity_id,
            "workload_id": self.workload_id,
            "bytes_transferred": self.bytes_transferred,
            "record_count": self.record_count,
            "classification": self.classification.value if isinstance(self.classification, ClassificationLevel) else self.classification,
            "channel": self.channel.value if isinstance(self.channel, DataFlowChannel) else self.channel,
            "is_external_destination": self.is_external_destination,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class DataFlowMonitor:
    """Ingests and records data movement telemetry across enterprise endpoints and data stores."""

    def __init__(self):
        self._events: List[DataMovementEvent] = []

    def record_movement(self, event: DataMovementEvent) -> None:
        self._events.append(event)

    def list_events(self, asset_id: Optional[str] = None) -> List[DataMovementEvent]:
        if asset_id:
            return [e for e in self._events if e.source_asset_id == asset_id or e.destination_id == asset_id]
        return list(self._events)
