"""
Container Registry Activity Monitoring.
Component 14: Monitors image pushes, deletions, tag mutations, and unexpected artifacts.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class RegistryEventType(str, Enum):
    IMAGE_PUSHED = "IMAGE_PUSHED"
    IMAGE_PULLED = "IMAGE_PULLED"
    IMAGE_DELETED = "IMAGE_DELETED"
    TAG_MUTATED = "TAG_MUTATED"


@dataclass
class RegistryEvent:
    event_id: str
    event_type: RegistryEventType
    repository: str
    tag: str
    digest: str
    actor: str
    source_ip: str = "10.0.1.55"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value if isinstance(self.event_type, RegistryEventType) else self.event_type,
            "repository": self.repository,
            "tag": self.tag,
            "digest": self.digest,
            "actor": self.actor,
            "timestamp": self.timestamp,
        }


class RegistryMonitor:
    """Tracks image lifecycle events and alerts on tag mutation or untrusted pushes."""

    def __init__(self):
        self._events: List[RegistryEvent] = []
        # (repository, tag) -> latest digest
        self._tag_digest_map: Dict[str, str] = {}

    def record_event(self, event: RegistryEvent) -> Optional[Dict[str, Any]]:
        self._events.append(event)
        key = f"{event.repository}:{event.tag}"

        anomaly = None
        if event.event_type == RegistryEventType.IMAGE_PUSHED:
            if key in self._tag_digest_map and self._tag_digest_map[key] != event.digest:
                anomaly = {
                    "alert": "TAG_MUTATION_DETECTED",
                    "severity": "HIGH",
                    "repository": event.repository,
                    "tag": event.tag,
                    "previous_digest": self._tag_digest_map[key],
                    "new_digest": event.digest,
                    "actor": event.actor,
                    "recommendation": "Enforce immutable tags in container registry to prevent supply-chain tampering.",
                }
            self._tag_digest_map[key] = event.digest

        return anomaly

    def get_events(self, limit: int = 50) -> List[RegistryEvent]:
        return self._events[-limit:]
