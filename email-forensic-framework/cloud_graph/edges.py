"""
Cloud Security Graph Edges and Relationships.
Components 40, 41, 42: Models access, containment, communication, and assumption relationships.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum
import time


class CloudEdgeType(str, Enum):
    ASSUMES = "ASSUMES"
    MEMBER_OF = "MEMBER_OF"
    HOSTS = "HOSTS"
    CONTAINS = "CONTAINS"
    RUNS_IN = "RUNS_IN"
    ACCESSES = "ACCESSES"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    ENCRYPTS_WITH = "ENCRYPTS_WITH"
    EXPOSES = "EXPOSES"


@dataclass
class CloudEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: CloudEdgeType
    allowed: bool = True
    policy_id: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value if isinstance(self.edge_type, CloudEdgeType) else self.edge_type,
            "allowed": self.allowed,
            "policy_id": self.policy_id,
            "properties": self.properties,
            "timestamp": self.timestamp,
        }
