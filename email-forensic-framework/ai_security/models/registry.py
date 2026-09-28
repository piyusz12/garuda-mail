"""AI Model Registry and Version Management.
Components 30.3, 30.7, 30.44: Registry of enterprise-approved AI models, formats, parameters, and deprecation states.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from ai_security.inventory.assets import ModelLifecycleStatus


class ModelFormat(str, Enum):
    GGUF = "GGUF"
    SAFETENSORS = "SAFETENSORS"
    ONNX = "ONNX"
    PYTORCH = "PYTORCH"
    REMOTE_API = "REMOTE_API"


@dataclass
class ModelMetadata:
    model_id: str
    name: str
    version: str
    format: ModelFormat
    parameter_count: str
    context_window: int
    license: str
    is_fine_tuned: bool = False
    base_model: Optional[str] = None
    approved_for_production: bool = True
    lifecycle_status: ModelLifecycleStatus = ModelLifecycleStatus.ACTIVE
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "name": self.name,
            "version": self.version,
            "format": self.format.value,
            "parameter_count": self.parameter_count,
            "context_window": self.context_window,
            "license": self.license,
            "is_fine_tuned": self.is_fine_tuned,
            "base_model": self.base_model,
            "approved_for_production": self.approved_for_production,
            "lifecycle_status": self.lifecycle_status.value,
            "registered_at": self.registered_at,
        }


class AIModelRegistry:
    """Enterprise registry governing model approval, deprecation, and configuration metadata."""

    def __init__(self):
        self._models: Dict[str, ModelMetadata] = {}
        self._seed_default_models()

    def _seed_default_models(self):
        self.register_model(
            ModelMetadata(
                model_id="MODEL-781",
                name="qwen2.5-8b-instruct",
                version="2.5-8b",
                format=ModelFormat.GGUF,
                parameter_count="8B",
                context_window=32768,
                license="Apache-2.0",
                approved_for_production=True,
                lifecycle_status=ModelLifecycleStatus.ACTIVE,
            )
        )
        self.register_model(
            ModelMetadata(
                model_id="MODEL-101",
                name="legacy-llama2-7b-chat",
                version="1.0",
                format=ModelFormat.PYTORCH,
                parameter_count="7B",
                context_window=4096,
                license="Llama-2-Community",
                approved_for_production=False,
                lifecycle_status=ModelLifecycleStatus.DEPRECATED,
            )
        )

    def register_model(self, model: ModelMetadata) -> None:
        self._models[model.model_id] = model

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        return self._models.get(model_id)

    def list_models(self, status: Optional[ModelLifecycleStatus] = None) -> List[ModelMetadata]:
        models = list(self._models.values())
        if status:
            models = [m for m in models if m.lifecycle_status == status]
        return models

    def set_lifecycle_status(self, model_id: str, status: ModelLifecycleStatus) -> Optional[ModelMetadata]:
        m = self.get_model(model_id)
        if m:
            m.lifecycle_status = status
            if status in (ModelLifecycleStatus.DEPRECATED, ModelLifecycleStatus.BLOCKED, ModelLifecycleStatus.RETIRED):
                m.approved_for_production = False
        return m
