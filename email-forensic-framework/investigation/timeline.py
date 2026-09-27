"""
Phase 23 - Forensic Timeline Builder.
Constructs chronological sequence of events, certificate changes, and detection triggers.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

@dataclass
class TimelineEvent:
    timestamp: datetime
    event_type: str
    entity: str
    description: str
    evidence_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class TimelineBuilder:
    """Assembles and orders chronological timeline entries."""

    def __init__(self):
        self.events: List[TimelineEvent] = []

    def add_event(self, timestamp: datetime, event_type: str, entity: str, description: str, evidence_id: str, metadata: Optional[Dict[str, Any]] = None):
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type=event_type,
            entity=entity,
            description=description,
            evidence_id=evidence_id,
            metadata=metadata or {}
        ))
        self.events.sort(key=lambda x: x.timestamp)

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "entity": e.entity,
                "description": e.description,
                "evidence_id": e.evidence_id,
                "metadata": e.metadata
            }
            for e in self.events
        ]
