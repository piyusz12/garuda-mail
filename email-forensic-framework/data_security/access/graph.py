"""
Data Access Relationship Graph.
Component 29.9: Maps identities, workloads, service accounts, and data store permissions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import time


@dataclass
class DataAccessBinding:
    binding_id: str
    identity_id: str
    workload_id: Optional[str]
    asset_id: str
    permission: str  # READ, WRITE, ADMIN, EXPORT
    granted_by: str = "IAM-Role-Policy"
    is_active: bool = True
    granted_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "identity_id": self.identity_id,
            "workload_id": self.workload_id,
            "asset_id": self.asset_id,
            "permission": self.permission,
            "granted_by": self.granted_by,
            "is_active": self.is_active,
            "granted_at": self.granted_at,
        }


class DataAccessGraph:
    """Maintains mapping of direct and role-based data access permissions."""

    def __init__(self):
        self._bindings: Dict[str, DataAccessBinding] = {}
        self._seed_default_bindings()

    def _seed_default_bindings(self):
        defaults = [
            DataAccessBinding("B1", "USER-1192", None, "DATA-8821", "READ", "Analyst-Role"),
            DataAccessBinding("B2", "SERVICE-91", "WORKLOAD-991", "DATA-8821", "READ", "MTA-Service-Role"),
            DataAccessBinding("B3", "DBA-ADMIN-01", None, "DATA-8821", "ADMIN", "Direct-Grant"),
            DataAccessBinding("B4", "SERVICE-FORENSIC", "WORKLOAD-101", "DATA-FORENSIC-01", "READ", "Forensic-Service-Role"),
        ]
        for b in defaults:
            self.add_binding(b)

    def add_binding(self, binding: DataAccessBinding) -> None:
        self._bindings[binding.binding_id] = binding

    def get_bindings_for_asset(self, asset_id: str) -> List[DataAccessBinding]:
        return [b for b in self._bindings.values() if b.asset_id == asset_id and b.is_active]

    def get_bindings_for_identity(self, identity_id: str) -> List[DataAccessBinding]:
        return [b for b in self._bindings.values() if b.identity_id == identity_id and b.is_active]
