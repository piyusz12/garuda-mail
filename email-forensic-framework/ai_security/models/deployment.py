"""AI Model Serving and Runtime Configuration Security.
Components 30.7, 30.8, 30.14: Tracks runtime configuration (context length, temperature, system prompts, authentication, rate limits).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class ModelServingConfig:
    deployment_id: str
    model_id: str
    endpoint_url: str
    host_node: str
    port: int
    context_length: int = 32768
    temperature: float = 0.7
    system_prompt_hash: str = ""
    requires_authentication: bool = True
    authorized_callers: List[str] = field(default_factory=list)
    rate_limit_rpm: int = 600
    egress_network_allowed: bool = False
    deployed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_id": self.deployment_id,
            "model_id": self.model_id,
            "endpoint_url": self.endpoint_url,
            "host_node": self.host_node,
            "port": self.port,
            "context_length": self.context_length,
            "temperature": self.temperature,
            "system_prompt_hash": self.system_prompt_hash,
            "requires_authentication": self.requires_authentication,
            "authorized_callers": self.authorized_callers,
            "rate_limit_rpm": self.rate_limit_rpm,
            "egress_network_allowed": self.egress_network_allowed,
            "deployed_at": self.deployed_at,
        }


class ModelDeploymentManager:
    """Manages active model server endpoints and enforces caller authentication."""

    def __init__(self):
        self._deployments: Dict[str, ModelServingConfig] = {}
        self._seed_default_deployments()

    def _seed_default_deployments(self):
        self.register_deployment(
            ModelServingConfig(
                deployment_id="DEP-VLLM-NODE04",
                model_id="MODEL-781",
                endpoint_url="http://ai-node-04.internal:8000/v1/chat/completions",
                host_node="AI-NODE-04",
                port=8000,
                context_length=32768,
                temperature=0.2,
                requires_authentication=True,
                authorized_callers=["AGENT-41", "AI-APP-19", "SERVICE-IDENTITY-77"],
                rate_limit_rpm=1200,
                egress_network_allowed=False,  # Air-gapped local model
            )
        )

    def register_deployment(self, config: ModelServingConfig) -> None:
        self._deployments[config.deployment_id] = config

    def get_deployment(self, deployment_id: str) -> Optional[ModelServingConfig]:
        return self._deployments.get(deployment_id)

    def is_caller_authorized(self, deployment_id: str, caller_id: str) -> bool:
        dep = self._deployments.get(deployment_id)
        if not dep:
            return False
        if not dep.requires_authentication:
            return True
        return caller_id in dep.authorized_callers
