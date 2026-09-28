"""AI Security Graph Nodes.
Component 30.78: Node definitions representing models, agents, tools, vector stores, and destinations.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum


class AIGraphNodeType(str, Enum):
    USER = "USER"
    IDENTITY = "IDENTITY"
    APPLICATION = "APPLICATION"
    WORKLOAD = "WORKLOAD"
    AI_AGENT = "AI_AGENT"
    MODEL = "MODEL"
    MODEL_VERSION = "MODEL_VERSION"
    RAG_PIPELINE = "RAG_PIPELINE"
    DOCUMENT = "DOCUMENT"
    DATASET = "DATASET"
    VECTOR_STORE = "VECTOR_STORE"
    EMBEDDING = "EMBEDDING"
    TOOL = "TOOL"
    API = "API"
    DATABASE = "DATABASE"
    DESTINATION = "DESTINATION"
    POLICY = "POLICY"
    SECRET = "SECRET"


@dataclass
class AIGraphNode:
    node_id: str
    node_type: AIGraphNodeType
    label: str
    sensitivity_score: float = 0.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "sensitivity_score": self.sensitivity_score,
            "properties": self.properties,
        }
