"""AI Security Graph Edges and Relationships.
Component 30.78: Edge definitions representing invokes, reads, calls, exports, and dependencies.
"""
from dataclasses import dataclass, field
from typing import Dict, Any
from enum import Enum
import time


class AIGraphEdgeType(str, Enum):
    USES = "USES"
    INVOKES = "INVOKES"
    READS = "READS"
    RETRIEVES = "RETRIEVES"
    GENERATES = "GENERATES"
    CALLS = "CALLS"
    WRITES = "WRITES"
    EXPORTS = "EXPORTS"
    AUTHENTICATES = "AUTHENTICATES"
    AUTHORIZED_BY = "AUTHORIZED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    DEPLOYED_ON = "DEPLOYED_ON"
    DERIVED_FROM = "DERIVED_FROM"


@dataclass
class AIGraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: AIGraphEdgeType
    allowed: bool = True
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "allowed": self.allowed,
            "properties": self.properties,
            "timestamp": self.timestamp,
        }
