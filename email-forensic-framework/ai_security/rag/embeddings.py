"""Embedding Security Tracking.
Component 30.16: Links vector embeddings directly back to source datasets and tracks dimensionality and model version.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from data_security.inventory.normalization import ClassificationLevel


@dataclass
class EmbeddingModelMetadata:
    embedding_id: str
    model_name: str
    version: str
    dimension: int
    max_input_tokens: int
    source_dataset_id: str
    classification: ClassificationLevel
    is_local: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "embedding_id": self.embedding_id,
            "model_name": self.model_name,
            "version": self.version,
            "dimension": self.dimension,
            "max_input_tokens": self.max_input_tokens,
            "source_dataset_id": self.source_dataset_id,
            "classification": self.classification.value,
            "is_local": self.is_local,
            "created_at": self.created_at,
        }


class EmbeddingSecurityTracker:
    """Maintains provenance linkages between high-dimensional embeddings and enterprise source data."""

    def __init__(self):
        self._embeddings: Dict[str, EmbeddingModelMetadata] = {}
        self._seed_default_embeddings()

    def _seed_default_embeddings(self):
        self.register_embedding(
            EmbeddingModelMetadata(
                embedding_id="EMBED-01",
                model_name="bge-large-en-v1.5",
                version="1.5",
                dimension=1024,
                max_input_tokens=512,
                source_dataset_id="DATA-8821",
                classification=ClassificationLevel.RESTRICTED,
                is_local=True,
            )
        )

    def register_embedding(self, meta: EmbeddingModelMetadata) -> None:
        self._embeddings[meta.embedding_id] = meta

    def get_embedding(self, embedding_id: str) -> Optional[EmbeddingModelMetadata]:
        return self._embeddings.get(embedding_id)
