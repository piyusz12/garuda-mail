"""
Data Security Graph Edges and Relationships.
Component 29.66: Graph edges representing reads, writes, transformations, encryption, and exports.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum
import time


class DataGraphEdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    READS = "READS"
    WRITES = "WRITES"
    COPIES = "COPIES"
    TRANSFORMS = "TRANSFORMS"
    PUBLISHES = "PUBLISHES"
    EXPORTS = "EXPORTS"
    ENCRYPTED_BY = "ENCRYPTED_BY"
    OWNED_BY = "OWNED_BY"
    AUTHORIZED_BY = "AUTHORIZED_BY"


@dataclass
class DataGraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: DataGraphEdgeType
    allowed: bool = True
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value if isinstance(self.edge_type, DataGraphEdgeType) else self.edge_type,
            "allowed": self.allowed,
            "properties": self.properties,
            "timestamp": self.timestamp,
        }
