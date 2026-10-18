"""Garuda Distributed Sovereign AI Fabric - Model Placement & Replication.
Phase 34 Sections 34.9, 34.10, 34.52:
Model catalog, required VRAM validation, placement states,
and cross-node model replication.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time

from fabric.models import (
    ModelLifecycleStatus,
    NetworkZone,
    FabricNodeRecord,
)
from fabric.node_registry import NodeRegistry


@dataclass
class FabricModelSpec:
    model_id: str
    name: str
    parameter_size: str
    required_vram_gb: float
    required_ram_gb: float
    capabilities: List[str]
    allowed_zones: List[NetworkZone]
    is_sovereign_approved: bool = True
    context_length: int = 32768
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "name": self.name,
            "parameter_size": self.parameter_size,
            "required_vram_gb": self.required_vram_gb,
            "required_ram_gb": self.required_ram_gb,
            "capabilities": self.capabilities,
            "allowed_zones": [z.value for z in self.allowed_zones],
            "is_sovereign_approved": self.is_sovereign_approved,
            "context_length": self.context_length,
            "description": self.description,
        }


class ModelPlacementManager:
    """Orchestrates model lifecycle, placement validation, and replication across nodes."""

    def __init__(self, registry: NodeRegistry):
        self.registry = registry
        self._catalog: Dict[str, FabricModelSpec] = {}
        self._seed_model_catalog()

    def _seed_model_catalog(self):
        self.register_model(
            FabricModelSpec(
                model_id="qwen-local",
                name="Qwen-2.5-1.5B-Instruct-GGUF",
                parameter_size="1.5B",
                required_vram_gb=2.2,
                required_ram_gb=4.0,
                capabilities=["chat", "coding", "llm_inference", "rag"],
                allowed_zones=[NetworkZone.RESTRICTED_AI, NetworkZone.INTERNAL_AI, NetworkZone.GENERAL_AI],
                is_sovereign_approved=True,
                context_length=32768,
                description="Ultra-fast local model optimized for RTX 4060 and edge workstations.",
            )
        )
        self.register_model(
            FabricModelSpec(
                model_id="qwen-coder-7b",
                name="Qwen-2.5-Coder-7B-Instruct",
                parameter_size="7B",
                required_vram_gb=6.5,
                required_ram_gb=12.0,
                capabilities=["coding", "llm_inference", "chat"],
                allowed_zones=[NetworkZone.RESTRICTED_AI, NetworkZone.INTERNAL_AI],
                is_sovereign_approved=True,
                context_length=65536,
                description="Specialized high-accuracy coding model.",
            )
        )
        self.register_model(
            FabricModelSpec(
                model_id="qwen-vl-vision",
                name="Qwen-2.5-VL-7B-Vision",
                parameter_size="7B",
                required_vram_gb=7.8,
                required_ram_gb=16.0,
                capabilities=["vision", "image_processing", "video_analysis", "llm_inference"],
                allowed_zones=[NetworkZone.INTERNAL_AI, NetworkZone.GENERAL_AI],
                is_sovereign_approved=True,
                context_length=32768,
                description="High-precision visual and multimodal forensic inspection model.",
            )
        )
        self.register_model(
            FabricModelSpec(
                model_id="bge-embeddings",
                name="BAAI BGE-Large-EN-v1.5",
                parameter_size="0.5B",
                required_vram_gb=1.2,
                required_ram_gb=2.0,
                capabilities=["embeddings", "reranking"],
                allowed_zones=[NetworkZone.RESTRICTED_AI, NetworkZone.INTERNAL_AI, NetworkZone.STORAGE_NET],
                is_sovereign_approved=True,
                context_length=8192,
                description="Dense forensic retrieval and document embedding model.",
            )
        )
        self.register_model(
            FabricModelSpec(
                model_id="llama-3-70b",
                name="Meta-Llama-3-70B-Instruct",
                parameter_size="70B",
                required_vram_gb=40.0,
                required_ram_gb=64.0,
                capabilities=["chat", "llm_inference", "reasoning"],
                allowed_zones=[NetworkZone.INTERNAL_AI],
                is_sovereign_approved=True,
                context_length=131072,
                description="High-capacity frontier model requiring distributed GPU cluster.",
            )
        )

    def register_model(self, spec: FabricModelSpec) -> None:
        self._catalog[spec.model_id] = spec

    def get_model(self, model_id: str) -> Optional[FabricModelSpec]:
        return self._catalog.get(model_id)

    def list_catalog(self) -> List[FabricModelSpec]:
        return list(self._catalog.values())

    def can_place_model(self, model_id: str, node: FabricNodeRecord) -> tuple[bool, str]:
        """Validates if a model can be placed on a node based on VRAM and network zone."""
        spec = self._catalog.get(model_id)
        if not spec:
            return False, f"Model '{model_id}' not found in catalog"

        # Check zone authorization
        if node.network_zone not in spec.allowed_zones:
            return False, f"Node zone '{node.network_zone.value}' not allowed for model '{model_id}'"

        # Check available VRAM (if GPU model)
        if spec.required_vram_gb > 0:
            if node.free_vram_gb < spec.required_vram_gb:
                return False, (
                    f"Insufficient VRAM on {node.node_id}: required {spec.required_vram_gb} GB, "
                    f"available {node.free_vram_gb} GB"
                )

        return True, "Eligible for placement"

    def place_model(self, model_id: str, node_id: str) -> tuple[bool, str]:
        """Deploys/loads a model onto a target node."""
        node = self.registry.get_node(node_id)
        if not node:
            return False, f"Node '{node_id}' not found"

        eligible, reason = self.can_place_model(model_id, node)
        if not eligible:
            return False, reason

        spec = self._catalog[model_id]
        node.models_loaded[model_id] = ModelLifecycleStatus.READY
        # Adjust simulated VRAM allocation
        node.vram_used_gb = round(min(node.vram_total_gb, node.vram_used_gb + spec.required_vram_gb), 2)
        return True, f"Model '{model_id}' placed and READY on {node_id}"

    def replicate_model(self, model_id: str, target_node_ids: List[str]) -> Dict[str, Any]:
        """Replicates a hot model across multiple approved nodes for load-balancing (Section 34.10)."""
        spec = self._catalog.get(model_id)
        if not spec:
            return {"success": False, "error": f"Model '{model_id}' not found in catalog"}

        results = {}
        successful_placements = []

        for nid in target_node_ids:
            node = self.registry.get_node(nid)
            if not node:
                results[nid] = {"success": False, "reason": "Node not found"}
                continue

            if node.models_loaded.get(model_id) == ModelLifecycleStatus.READY:
                results[nid] = {"success": True, "reason": "Already loaded"}
                successful_placements.append(nid)
                continue

            ok, reason = self.place_model(model_id, nid)
            results[nid] = {"success": ok, "reason": reason}
            if ok:
                successful_placements.append(nid)

        return {
            "model_id": model_id,
            "replicated_count": len(successful_placements),
            "replicas": successful_placements,
            "details": results,
            "success": len(successful_placements) > 0,
        }

    def get_model_distribution(self) -> Dict[str, List[str]]:
        """Returns which nodes are currently serving which models."""
        dist: Dict[str, List[str]] = {}
        for node in self.registry.list_nodes():
            for m_id, state in node.models_loaded.items():
                if state == ModelLifecycleStatus.READY:
                    dist.setdefault(m_id, []).append(node.node_id)
        return dist
