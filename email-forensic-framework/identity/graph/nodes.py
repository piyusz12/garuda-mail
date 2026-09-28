"""
Identity Graph Node Definitions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class IdentityNodeType(str, Enum):
    PERSON = "PERSON"
    DEVICE = "DEVICE"
    SERVICE = "SERVICE"
    WORKLOAD = "WORKLOAD"
    GROUP = "GROUP"
    ROLE = "ROLE"
    CERTIFICATE = "CERTIFICATE"
    SESSION = "SESSION"


@dataclass
class IdentityNode:
    node_id: str
    node_type: IdentityNodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value if isinstance(self.node_type, IdentityNodeType) else self.node_type,
            "label": self.label,
            "properties": self.properties,
        }
