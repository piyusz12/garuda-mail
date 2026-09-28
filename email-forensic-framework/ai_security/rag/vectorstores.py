"""Vector Database Security and Tenant Isolation.
Component 30.17: Tracks vector DB collections, namespaces, multi-tenant isolation, and access controls.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class VectorCollectionRecord:
    collection_id: str
    vector_store_id: str
    collection_name: str
    tenant_id: str
    has_tenant_isolation: bool
    is_publicly_exposed: bool
    authorized_roles: List[str]
    total_vectors: int
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "vector_store_id": self.vector_store_id,
            "collection_name": self.collection_name,
            "tenant_id": self.tenant_id,
            "has_tenant_isolation": self.has_tenant_isolation,
            "is_publicly_exposed": self.is_publicly_exposed,
            "authorized_roles": self.authorized_roles,
            "total_vectors": self.total_vectors,
            "created_at": self.created_at,
        }


class VectorDatabaseManager:
    """Manages vector database collections and verifies tenant isolation."""

    def __init__(self):
        self._collections: Dict[str, VectorCollectionRecord] = {}
        self._seed_default_collections()

    def _seed_default_collections(self):
        self.register_collection(
            VectorCollectionRecord(
                collection_id="COLL-CUST-PROD",
                vector_store_id="VECTOR-DB-07",
                collection_name="kb-customer-docs",
                tenant_id="TENANT-CORP-PRIMARY",
                has_tenant_isolation=True,
                is_publicly_exposed=False,
                authorized_roles=["ROLE-SUPPORT", "ROLE-ENGINEERING", "AGENT-41"],
                total_vectors=45000,
            )
        )
        self.register_collection(
            VectorCollectionRecord(
                collection_id="COLL-FINANCE-PROD",
                vector_store_id="VECTOR-DB-07",
                collection_name="kb-finance-vault",
                tenant_id="TENANT-CORP-FINANCE",
                has_tenant_isolation=True,
                is_publicly_exposed=False,
                authorized_roles=["ROLE-CFO-AUDIT"],
                total_vectors=12000,
            )
        )

    def register_collection(self, rec: VectorCollectionRecord) -> None:
        self._collections[rec.collection_id] = rec

    def get_collection(self, collection_id: str) -> Optional[VectorCollectionRecord]:
        return self._collections.get(collection_id)

    def is_caller_authorized_for_collection(self, caller_id: str, collection_id: str) -> bool:
        c = self.get_collection(collection_id)
        if not c:
            return False
        return caller_id in c.authorized_roles
