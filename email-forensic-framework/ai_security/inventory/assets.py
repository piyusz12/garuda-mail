"""AI Asset Canonical Modeling.
Component 30.1 & 30.6: Canonical entity models for LLMs, agents, tools, RAG, and vector stores.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AIAssetType(str, Enum):
    LLM = "LLM"
    EMBEDDING_MODEL = "EMBEDDING_MODEL"
    RERANKER = "RERANKER"
    VISION_MODEL = "VISION_MODEL"
    SPEECH_MODEL = "SPEECH_MODEL"
    CLASSIFIER = "CLASSIFIER"
    AGENT = "AGENT"
    RAG_PIPELINE = "RAG_PIPELINE"
    VECTOR_STORE = "VECTOR_STORE"
    MODEL_SERVER = "MODEL_SERVER"
    TOOL_SERVER = "TOOL_SERVER"
    AI_APPLICATION = "AI_APPLICATION"
    AI_WORKFLOW = "AI_WORKFLOW"


class ModelLifecycleStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    BLOCKED = "BLOCKED"
    RETIRED = "RETIRED"


class DeploymentEnvironment(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    SOVEREIGN_AIRGAP = "SOVEREIGN_AIRGAP"


@dataclass
class AIAsset:
    ai_asset_id: str
    name: str
    asset_type: AIAssetType
    owner: str = "ai-platform@garuda.enterprise"
    environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION
    provider: str = "self-hosted"  # "self-hosted", "aws-bedrock", "azure-openai", "ollama", "vllm"
    version: str = "1.0.0"
    location: str = "us-east-1"
    status: ModelLifecycleStatus = ModelLifecycleStatus.ACTIVE
    risk_level: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    is_external: bool = False
    is_sovereign_compliant: bool = True
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ai_asset_id": self.ai_asset_id,
            "name": self.name,
            "asset_type": self.asset_type.value if isinstance(self.asset_type, AIAssetType) else self.asset_type,
            "owner": self.owner,
            "environment": self.environment.value if isinstance(self.environment, DeploymentEnvironment) else self.environment,
            "provider": self.provider,
            "version": self.version,
            "location": self.location,
            "status": self.status.value if isinstance(self.status, ModelLifecycleStatus) else self.status,
            "risk_level": self.risk_level,
            "is_external": self.is_external,
            "is_sovereign_compliant": self.is_sovereign_compliant,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }
