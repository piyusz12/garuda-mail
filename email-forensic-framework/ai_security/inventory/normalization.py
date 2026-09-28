"""AI Asset Normalization.
Component 30.1: Normalizes disparate models, agents, vector stores, and tools into canonical AIAsset representations.
"""
from typing import Dict, List, Optional, Any
from ai_security.inventory.assets import AIAsset, AIAssetType, ModelLifecycleStatus, DeploymentEnvironment


class AIAssetNormalizer:
    """Normalizes model registries, agent manifests, and tool configurations into canonical AIAsset entities."""

    @classmethod
    def normalize_model(
        cls,
        model_id: str,
        name: str,
        version: str,
        provider: str = "self-hosted",
        location: str = "AI-NODE-04",
        is_external: bool = False,
        artifact_hash: str = "",
        parameters: str = "8B",
    ) -> AIAsset:
        return AIAsset(
            ai_asset_id=model_id,
            name=name,
            asset_type=AIAssetType.LLM,
            provider=provider,
            version=version,
            location=location,
            status=ModelLifecycleStatus.ACTIVE,
            is_external=is_external,
            is_sovereign_compliant=not is_external,
            metadata={
                "artifact_hash": artifact_hash,
                "parameters": parameters,
            },
        )

    @classmethod
    def normalize_agent(
        cls,
        agent_id: str,
        name: str,
        owner: str,
        associated_model: str,
        tools: List[str],
        data_sources: List[str],
    ) -> AIAsset:
        return AIAsset(
            ai_asset_id=agent_id,
            name=name,
            asset_type=AIAssetType.AGENT,
            owner=owner,
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="HIGH" if len(tools) > 3 else "MEDIUM",
            metadata={
                "model_id": associated_model,
                "tools": tools,
                "data_sources": data_sources,
            },
        )

    @classmethod
    def normalize_rag_pipeline(
        cls,
        pipeline_id: str,
        name: str,
        vector_store_id: str,
        embedding_model_id: str,
        knowledge_bases: List[str],
    ) -> AIAsset:
        return AIAsset(
            ai_asset_id=pipeline_id,
            name=name,
            asset_type=AIAssetType.RAG_PIPELINE,
            status=ModelLifecycleStatus.ACTIVE,
            metadata={
                "vector_store_id": vector_store_id,
                "embedding_model_id": embedding_model_id,
                "knowledge_bases": knowledge_bases,
            },
        )
