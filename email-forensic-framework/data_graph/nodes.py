"""
Data Security Graph Nodes and Entities.
Component 29.66: Graph nodes representing datasets, tables, columns, identities, workloads, databases, and encryption keys.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class DataGraphNodeType(str, Enum):
    DATASET = "DATASET"
    TABLE = "TABLE"
    COLUMN = "COLUMN"
    OBJECT = "OBJECT"
    STREAM = "STREAM"
    API = "API"
    USER = "USER"
    WORKLOAD = "WORKLOAD"
    DATABASE = "DATABASE"
    STORAGE = "STORAGE"
    TRANSFORMATION = "TRANSFORMATION"
    DESTINATION = "DESTINATION"
    POLICY = "POLICY"
    KEY = "KEY"


@dataclass
class DataGraphNode:
    node_id: str
    node_type: DataGraphNodeType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    sensitivity_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value if isinstance(self.node_type, DataGraphNodeType) else self.node_type,
            "name": self.name,
            "properties": self.properties,
            "sensitivity_score": self.sensitivity_score,
        }
