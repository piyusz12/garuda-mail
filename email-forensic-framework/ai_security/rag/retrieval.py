"""Retrieval Authorization and Pre-Query Access Control.
Component 30.18: Enforces data-level authorization prior to vector similarity search.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from ai_security.rag.knowledge_base import KnowledgeBaseRegistry
from ai_security.rag.vectorstores import VectorDatabaseManager


@dataclass
class RetrievalEventRecord:
    event_id: str
    caller_id: str
    target_kb_id: str
    collection_id: str
    query_text: str
    is_authorized: bool
    retrieved_chunks_count: int
    decision_reason: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "caller_id": self.caller_id,
            "target_kb_id": self.target_kb_id,
            "collection_id": self.collection_id,
            "query_text": self.query_text,
            "is_authorized": self.is_authorized,
            "retrieved_chunks_count": self.retrieved_chunks_count,
            "decision_reason": self.decision_reason,
            "timestamp": self.timestamp,
        }


class RetrievalAuthorizationEngine:
    """Enforces pre-retrieval access control, preventing unauthorized vector queries before execution."""

    def __init__(
        self,
        kb_registry: Optional[KnowledgeBaseRegistry] = None,
        vdb_manager: Optional[VectorDatabaseManager] = None,
    ):
        self.kb_registry = kb_registry or KnowledgeBaseRegistry()
        self.vdb_manager = vdb_manager or VectorDatabaseManager()
        self._retrieval_events: List[RetrievalEventRecord] = []

    def evaluate_retrieval_request(
        self,
        caller_id: str,
        kb_id: str,
        query_text: str,
    ) -> RetrievalEventRecord:
        kb = self.kb_registry.get_kb(kb_id)
        if not kb:
            event = RetrievalEventRecord(
                event_id=f"RET-EVT-{int(time.time()*1000)}",
                caller_id=caller_id,
                target_kb_id=kb_id,
                collection_id="UNKNOWN",
                query_text=query_text,
                is_authorized=False,
                retrieved_chunks_count=0,
                decision_reason=f"Target knowledge base {kb_id} does not exist in registry.",
            )
            self._retrieval_events.append(event)
            return event

        # Check authorization before retrieval
        is_auth = (caller_id in kb.allowed_identities) or (caller_id in kb.allowed_agents)
        if not is_auth:
            event = RetrievalEventRecord(
                event_id=f"RET-EVT-{int(time.time()*1000)}",
                caller_id=caller_id,
                target_kb_id=kb_id,
                collection_id=kb.collection_name,
                query_text=query_text,
                is_authorized=False,
                retrieved_chunks_count=0,
                decision_reason=f"DENIED: Caller {caller_id} lacks access rights to {kb.classification.value} knowledge base {kb_id}.",
            )
            self._retrieval_events.append(event)
            return event

        event = RetrievalEventRecord(
            event_id=f"RET-EVT-{int(time.time()*1000)}",
            caller_id=caller_id,
            target_kb_id=kb_id,
            collection_id=kb.collection_name,
            query_text=query_text,
            is_authorized=True,
            retrieved_chunks_count=3,
            decision_reason=f"AUTHORIZED: Caller {caller_id} permitted to query {kb_id}.",
        )
        self._retrieval_events.append(event)
        return event

    def list_retrieval_events(self) -> List[RetrievalEventRecord]:
        return list(self._retrieval_events)
