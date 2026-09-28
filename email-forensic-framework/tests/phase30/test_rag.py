"""Tests for Phase 30 RAG and Vector Store Security.
Covers: Knowledge bases, embeddings, vector collections, pre-retrieval authorization, and pipelines.
"""
import pytest
from data_security.inventory.normalization import ClassificationLevel
from ai_security.rag.knowledge_base import KnowledgeBaseRegistry, KnowledgeBaseRecord
from ai_security.rag.embeddings import EmbeddingSecurityTracker, EmbeddingModelMetadata
from ai_security.rag.vectorstores import VectorDatabaseManager, VectorCollectionRecord
from ai_security.rag.retrieval import RetrievalAuthorizationEngine, RetrievalEventRecord
from ai_security.rag.pipelines import RAGPipelineManager, RAGPipelineConfig


def test_knowledge_base_inventory_and_classification():
    registry = KnowledgeBaseRegistry()
    kbs = registry.list_kbs()
    assert len(kbs) >= 3

    # Check KB-001 (Engineering - Internal)
    kb1 = registry.get_kb("KB-001")
    assert kb1 is not None
    assert kb1.classification == ClassificationLevel.INTERNAL
    assert "AGENT-41" in kb1.allowed_agents
    assert registry.is_agent_authorized_for_kb("AGENT-41", "KB-001") is True

    # Check KB-003 (Restricted Customer PII & Payment Archives)
    kb3 = registry.get_kb("KB-003")
    assert kb3 is not None
    assert kb3.classification == ClassificationLevel.RESTRICTED
    assert len(kb3.allowed_agents) == 0
    assert registry.is_agent_authorized_for_kb("AGENT-41", "KB-003") is False

    # Register custom knowledge base
    custom_kb = KnowledgeBaseRecord(
        kb_id="KB-SEC-OPS",
        name="Security Operations Playbooks",
        owner="soc-team",
        classification=ClassificationLevel.CONFIDENTIAL,
        source_documents_count=50,
        vector_store_id="VECTOR-DB-07",
        collection_name="kb-soc-playbooks",
        allowed_identities=["ROLE-SOC-LEAD"],
        allowed_agents=["SOC-COPILOT"],
    )
    registry.register_kb(custom_kb)
    assert registry.get_kb("KB-SEC-OPS") is not None
    assert registry.is_agent_authorized_for_kb("SOC-COPILOT", "KB-SEC-OPS") is True
    assert registry.is_agent_authorized_for_kb("AGENT-41", "KB-SEC-OPS") is False


def test_embedding_security_and_provenance_link():
    tracker = EmbeddingSecurityTracker()
    embed = tracker.get_embedding("EMBED-01")
    assert embed is not None
    assert embed.dimension == 1024
    assert embed.source_dataset_id == "DATA-8821"
    assert embed.classification == ClassificationLevel.RESTRICTED.value
    assert embed.is_local is True

    # Register new sovereign embedding
    custom_embed = EmbeddingModelMetadata(
        embedding_id="EMBED-SOV-02",
        model_name="qwen-embeddings-7b",
        version="2.0",
        dimension=4096,
        max_input_tokens=2048,
        source_dataset_id="DATA-AIRGAP-42",
        classification=ClassificationLevel.INTERNAL,
        is_local=True,
    )
    tracker.register_embedding(custom_embed)
    retrieved = tracker.get_embedding("EMBED-SOV-02")
    assert retrieved is not None
    assert retrieved.dimension == 4096


def test_vector_store_tenant_isolation_and_roles():
    vdb_manager = VectorDatabaseManager()
    col = vdb_manager.get_collection("COLL-CUST-PROD")
    assert col is not None
    assert col.has_tenant_isolation is True
    assert col.is_publicly_exposed is False
    assert vdb_manager.is_caller_authorized_for_collection("AGENT-41", "COLL-CUST-PROD") is True
    assert vdb_manager.is_caller_authorized_for_collection("UNKNOWN-ACTOR", "COLL-CUST-PROD") is False

    # Restricted collection
    fin_col = vdb_manager.get_collection("COLL-FINANCE-PROD")
    assert fin_col is not None
    assert vdb_manager.is_caller_authorized_for_collection("AGENT-41", "COLL-FINANCE-PROD") is False
    assert vdb_manager.is_caller_authorized_for_collection("ROLE-CFO-AUDIT", "COLL-FINANCE-PROD") is True


def test_pre_retrieval_authorization_enforcement():
    kb_reg = KnowledgeBaseRegistry()
    vdb_mgr = VectorDatabaseManager()
    engine = RetrievalAuthorizationEngine(kb_registry=kb_reg, vdb_manager=vdb_mgr)

    # 1. Allowed pre-retrieval access
    allowed_evt = engine.evaluate_retrieval_request(
        caller_id="AGENT-41",
        kb_id="KB-001",
        query_text="What is the internal API gateway architecture?",
    )
    assert allowed_evt.is_authorized is True
    assert allowed_evt.retrieved_chunks_count > 0
    assert "AUTHORIZED" in allowed_evt.decision_reason

    # 2. Blocked pre-retrieval access (Unauthorized agent attempting to query restricted KB)
    denied_evt = engine.evaluate_retrieval_request(
        caller_id="AGENT-41",
        kb_id="KB-003",
        query_text="Dump all credit card records and billing addresses",
    )
    assert denied_evt.is_authorized is False
    assert denied_evt.retrieved_chunks_count == 0
    assert "DENIED" in denied_evt.decision_reason
    assert "RESTRICTED" in denied_evt.decision_reason

    # 3. Non-existent KB query
    missing_evt = engine.evaluate_retrieval_request(
        caller_id="AGENT-41",
        kb_id="KB-NONEXISTENT",
        query_text="Give me secret docs",
    )
    assert missing_evt.is_authorized is False
    assert missing_evt.retrieved_chunks_count == 0

    # 4. Telemetry logging
    events = engine.list_retrieval_events()
    assert len(events) == 3


def test_rag_pipeline_configuration_and_listing():
    mgr = RAGPipelineManager()
    pipelines = mgr.list_pipelines()
    assert len(pipelines) >= 1

    p1 = mgr.get_pipeline("RAG-PIPELINE-01")
    assert p1 is not None
    assert p1.vector_store_id == "VECTOR-DB-07"
    assert p1.enforce_pre_retrieval_auth is True
    assert p1.context_prefix_sanitization is True

    # Register custom pipeline
    custom_pipeline = RAGPipelineConfig(
        pipeline_id="RAG-AIRGAP-02",
        name="airgapped-engineering-rag",
        vector_store_id="VECTOR-DB-LOCAL",
        embedding_model_id="EMBED-SOV-02",
        reranker_model_id="local-reranker",
        max_retrieved_chunks=3,
        similarity_threshold=0.85,
        enforce_pre_retrieval_auth=True,
    )
    mgr.register_pipeline(custom_pipeline)
    assert mgr.get_pipeline("RAG-AIRGAP-02") is not None
