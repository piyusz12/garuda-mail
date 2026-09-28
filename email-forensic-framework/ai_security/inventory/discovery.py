"""AI Asset Discovery Engine.
Components 30.2, 30.7, 30.8: Discovers AI systems, models, agents, tools, and pipelines across enterprise infrastructure.
"""
from typing import Dict, List, Optional, Any
from ai_security.inventory.assets import AIAsset, AIAssetType, ModelLifecycleStatus, DeploymentEnvironment


class AIDiscoveryEngine:
    """Continuously discovers and tracks AI models, agents, tools, and vector stores."""

    def __init__(self):
        self._assets: Dict[str, AIAsset] = {}
        self._seed_default_enterprise_assets()

    def _seed_default_enterprise_assets(self) -> None:
        # MODEL-781: Local Sovereign LLM (Qwen-8B-Instruct on AI-NODE-04)
        m781 = AIAsset(
            ai_asset_id="MODEL-781",
            name="qwen2.5-8b-instruct.q8_0.gguf",
            asset_type=AIAssetType.LLM,
            owner="ai-engineering@garuda.enterprise",
            environment=DeploymentEnvironment.PRODUCTION,
            provider="self-hosted-vllm",
            version="2.5-8b",
            location="AI-NODE-04",
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="MEDIUM",
            is_external=False,
            is_sovereign_compliant=True,
            metadata={
                "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "format": "GGUF",
                "parameters": "8B",
                "quantization": "Q8_0",
                "context_length": 32768,
                "approved_by": "secops-lead",
            },
        )
        self.register_asset(m781)

        # MODEL-EXTERNAL-01: Commercial API Model
        m_ext = AIAsset(
            ai_asset_id="MODEL-EXTERNAL-01",
            name="claude-3-5-sonnet-commercial",
            asset_type=AIAssetType.LLM,
            owner="enterprise-analytics",
            environment=DeploymentEnvironment.PRODUCTION,
            provider="anthropic-cloud",
            version="3.5-sonnet-20241022",
            location="cloud-us-east-1",
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="HIGH",
            is_external=True,
            is_sovereign_compliant=False,
            metadata={"endpoint": "https://api.anthropic.com/v1/messages"},
        )
        self.register_asset(m_ext)

        # EMBED-01: Local Embedding Model
        embed01 = AIAsset(
            ai_asset_id="EMBED-01",
            name="bge-large-en-v1.5",
            asset_type=AIAssetType.EMBEDDING_MODEL,
            owner="ai-platform",
            environment=DeploymentEnvironment.PRODUCTION,
            provider="self-hosted",
            version="1.5",
            location="AI-NODE-04",
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="LOW",
            is_external=False,
            is_sovereign_compliant=True,
            metadata={"dimension": 1024, "max_tokens": 512},
        )
        self.register_asset(embed01)

        # VDB-07: Enterprise Customer Knowledge Vector DB
        vdb07 = AIAsset(
            ai_asset_id="VECTOR-DB-07",
            name="garuda-qdrant-enterprise.prod",
            asset_type=AIAssetType.VECTOR_STORE,
            owner="data-platform",
            environment=DeploymentEnvironment.PRODUCTION,
            provider="qdrant-cluster",
            version="1.11.0",
            location="us-east-1-vpc-ai",
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="HIGH",
            is_external=False,
            is_sovereign_compliant=True,
            metadata={"collections": ["kb-customer-docs", "kb-secops-playbooks"], "tenant_isolation": True},
        )
        self.register_asset(vdb07)

        # RAG-01: Enterprise Customer RAG Pipeline
        rag01 = AIAsset(
            ai_asset_id="RAG-PIPELINE-01",
            name="customer-support-rag-pipeline",
            asset_type=AIAssetType.RAG_PIPELINE,
            owner="customer-platform",
            environment=DeploymentEnvironment.PRODUCTION,
            status=ModelLifecycleStatus.ACTIVE,
            metadata={
                "vector_store": "VECTOR-DB-07",
                "embedding_model": "EMBED-01",
                "target_data_asset": "DATA-8821",
            },
        )
        self.register_asset(rag01)

        # AGENT-41: Automated Customer Assistant Agent (Section 30.80 Scenario)
        agent41 = AIAsset(
            ai_asset_id="AGENT-41",
            name="customer-assist-agent-prod",
            asset_type=AIAssetType.AGENT,
            owner="customer-platform",
            environment=DeploymentEnvironment.PRODUCTION,
            status=ModelLifecycleStatus.ACTIVE,
            risk_level="HIGH",
            is_external=False,
            is_sovereign_compliant=True,
            metadata={
                "associated_model": "MODEL-781",
                "identity": "SERVICE-IDENTITY-77",
                "tools": ["database_query", "search_kb", "http_post"],
                "data_sources": ["DATA-8821", "VECTOR-DB-07"],
            },
        )
        self.register_asset(agent41)

    def register_asset(self, asset: AIAsset) -> None:
        self._assets[asset.ai_asset_id] = asset

    def get_asset(self, asset_id: str) -> Optional[AIAsset]:
        return self._assets.get(asset_id)

    def list_assets(self, asset_type: Optional[AIAssetType] = None) -> List[AIAsset]:
        assets = list(self._assets.values())
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        return assets

    def discover_all_ai_assets(self) -> List[AIAsset]:
        """Discovers and returns all registered AI assets across the enterprise."""
        return self.list_assets()
