"""RAG Pipeline Registry and Configuration Security.
Component 30.15: Manages RAG stages: Document ingestion, chunking, embedding, vector store, reranking, and context injection.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class RAGPipelineConfig:
    pipeline_id: str
    name: str
    vector_store_id: str
    embedding_model_id: str
    reranker_model_id: Optional[str]
    max_retrieved_chunks: int = 5
    similarity_threshold: float = 0.75
    enforce_pre_retrieval_auth: bool = True
    context_prefix_sanitization: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "name": self.name,
            "vector_store_id": self.vector_store_id,
            "embedding_model_id": self.embedding_model_id,
            "reranker_model_id": self.reranker_model_id,
            "max_retrieved_chunks": self.max_retrieved_chunks,
            "similarity_threshold": self.similarity_threshold,
            "enforce_pre_retrieval_auth": self.enforce_pre_retrieval_auth,
            "context_prefix_sanitization": self.context_prefix_sanitization,
            "created_at": self.created_at,
        }


class RAGPipelineManager:
    """Maintains enterprise RAG pipeline topologies and enforces telemetry at each stage."""

    def __init__(self):
        self._pipelines: Dict[str, RAGPipelineConfig] = {}
        self._seed_default_pipelines()

    def _seed_default_pipelines(self):
        self.register_pipeline(
            RAGPipelineConfig(
                pipeline_id="RAG-PIPELINE-01",
                name="customer-support-rag-pipeline",
                vector_store_id="VECTOR-DB-07",
                embedding_model_id="EMBED-01",
                reranker_model_id="bge-reranker-large",
                max_retrieved_chunks=4,
                similarity_threshold=0.80,
                enforce_pre_retrieval_auth=True,
                context_prefix_sanitization=True,
            )
        )

    def register_pipeline(self, pipeline: RAGPipelineConfig) -> None:
        self._pipelines[pipeline.pipeline_id] = pipeline

    def get_pipeline(self, pipeline_id: str) -> Optional[RAGPipelineConfig]:
        return self._pipelines.get(pipeline_id)

    def list_pipelines(self) -> List[RAGPipelineConfig]:
        return list(self._pipelines.values())
