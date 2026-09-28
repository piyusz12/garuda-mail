"""
Identity-to-Workload & Cloud Role Bindings.
Component 5 & 41: Bridges enterprise identities (Phase 27) to Cloud Roles and Kubernetes Workloads.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import uuid


@dataclass
class IAMBinding:
    binding_id: str
    identity_id: str  # User ID or Workload ID from Phase 27
    role_id: str      # CloudIAMRole ID
    scope_resource: str  # Cloud account, project, or Kubernetes cluster
    granted_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    is_active: bool = True

    def is_currently_valid(self) -> bool:
        if not self.is_active:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "identity_id": self.identity_id,
            "role_id": self.role_id,
            "scope_resource": self.scope_resource,
            "is_valid": self.is_currently_valid(),
            "granted_at": self.granted_at,
        }


class IdentityWorkloadBridge:
    """Manages bindings mapping enterprise identities to cloud permissions."""

    def __init__(self):
        self._bindings: Dict[str, IAMBinding] = {}
        self._load_defaults()

    def _load_defaults(self):
        b1 = IAMBinding(
            binding_id="BIND-SECOPS-ADMIN",
            identity_id="ID-1192",  # John Smith from Phase 27
            role_id="ROLE-K8S-ADMIN-01",
            scope_resource="RES-K8S-01",
        )
        b2 = IAMBinding(
            binding_id="BIND-WORKLOAD-MTA",
            identity_id="WORKLOAD-991",  # MTA Relay Workload from Phase 27
            role_id="ROLE-MTA-WORKLOAD-01",
            scope_resource="RES-BUCKET-EVIDENCE-01",
        )
        self._bindings[b1.binding_id] = b1
        self._bindings[b2.binding_id] = b2

    def create_binding(self, identity_id: str, role_id: str, scope: str, validity_hours: Optional[int] = None) -> IAMBinding:
        bid = f"BIND-{uuid.uuid4().hex[:6].upper()}"
        now = time.time()
        expires = now + (validity_hours * 3600) if validity_hours else None
        binding = IAMBinding(
            binding_id=bid,
            identity_id=identity_id,
            role_id=role_id,
            scope_resource=scope,
            granted_at=now,
            expires_at=expires,
        )
        self._bindings[bid] = binding
        return binding

    def get_bindings_for_identity(self, identity_id: str) -> List[IAMBinding]:
        return [b for b in self._bindings.values() if b.identity_id == identity_id and b.is_currently_valid()]

    def list_all(self) -> List[IAMBinding]:
        return list(self._bindings.values())
