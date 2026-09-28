"""Knowledge Base Security Inventory.
Component 30.19: Tracks enterprise knowledge bases, ownership, classification, and authorized consumers.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from data_security.inventory.normalization import ClassificationLevel


@dataclass
class KnowledgeBaseRecord:
    kb_id: str
    name: str
    owner: str
    classification: ClassificationLevel
    source_documents_count: int
    vector_store_id: str
    collection_name: str
    allowed_identities: List[str] = field(default_factory=list)
    allowed_agents: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kb_id": self.kb_id,
            "name": self.name,
            "owner": self.owner,
            "classification": self.classification.value,
            "source_documents_count": self.source_documents_count,
            "vector_store_id": self.vector_store_id,
            "collection_name": self.collection_name,
            "allowed_identities": self.allowed_identities,
            "allowed_agents": self.allowed_agents,
            "created_at": self.created_at,
        }


class KnowledgeBaseRegistry:
    """Enterprise registry tracking knowledge bases and their classification scopes."""

    def __init__(self):
        self._kbs: Dict[str, KnowledgeBaseRecord] = {}
        self._seed_default_kbs()

    def _seed_default_kbs(self):
        self.register_kb(
            KnowledgeBaseRecord(
                kb_id="KB-001",
                name="Internal Engineering Architecture & Docs",
                owner="engineering-platform",
                classification=ClassificationLevel.INTERNAL,
                source_documents_count=1450,
                vector_store_id="VECTOR-DB-07",
                collection_name="kb-eng-docs",
                allowed_identities=["USER-1192", "ROLE-ENGINEERING"],
                allowed_agents=["AGENT-41", "AGENT-DEV-BOT"],
            )
        )
        self.register_kb(
            KnowledgeBaseRecord(
                kb_id="KB-002",
                name="Customer Support Knowledge Base",
                owner="support-team",
                classification=ClassificationLevel.INTERNAL,
                source_documents_count=820,
                vector_store_id="VECTOR-DB-07",
                collection_name="kb-customer-docs",
                allowed_identities=["ROLE-SUPPORT", "USER-1192"],
                allowed_agents=["AGENT-41"],
            )
        )
        self.register_kb(
            KnowledgeBaseRecord(
                kb_id="KB-003",
                name="Restricted Customer PII & Payment Archives",
                owner="finance-compliance",
                classification=ClassificationLevel.RESTRICTED,
                source_documents_count=210,
                vector_store_id="VECTOR-DB-07",
                collection_name="kb-finance-vault",
                allowed_identities=["ROLE-CFO-AUDIT"],
                allowed_agents=[],  # No autonomous agents allowed!
            )
        )

    def register_kb(self, kb: KnowledgeBaseRecord) -> None:
        self._kbs[kb.kb_id] = kb

    def get_kb(self, kb_id: str) -> Optional[KnowledgeBaseRecord]:
        return self._kbs.get(kb_id)

    def list_kbs(self) -> List[KnowledgeBaseRecord]:
        return list(self._kbs.values())

    def is_agent_authorized_for_kb(self, agent_id: str, kb_id: str) -> bool:
        kb = self.get_kb(kb_id)
        if not kb:
            return False
        return agent_id in kb.allowed_agents
