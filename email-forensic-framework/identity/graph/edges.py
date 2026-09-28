"""
Identity Graph Edge Definitions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class IdentityEdgeType(str, Enum):
    OWNS = "OWNS"
    MEMBER_OF = "MEMBER_OF"
    USES = "USES"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    PRESENTS = "PRESENTS"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    HAS_ROLE = "HAS_ROLE"
    AUTHORIZED_FOR = "AUTHORIZED_FOR"


@dataclass
class IdentityEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: IdentityEdgeType
    valid_from: float = field(default_factory=time.time)
    valid_to: Optional[float] = None
    properties: Dict[str, Any] = field(default_factory=dict)

    def is_active_at(self, timestamp: float) -> bool:
        if timestamp < self.valid_from:
            return False
        if self.valid_to is not None and timestamp > self.valid_to:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value if isinstance(self.edge_type, IdentityEdgeType) else self.edge_type,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "properties": self.properties,
        }
