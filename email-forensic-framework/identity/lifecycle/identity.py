"""
Identity Lifecycle State Machine & Audit Tracking.
Manages states: CREATE -> ACTIVATE -> MODIFY -> SUSPEND -> REACTIVATE -> DEACTIVATE -> ARCHIVE.
"""
from typing import Dict, List, Optional, Any
import time

from identity.ingestion.users import UserIdentity, IdentityStatus


class IdentityLifecycleError(Exception):
    pass


class IdentityLifecycleManager:
    """Enforces state transitions and audit trails across the identity lifecycle."""

    ALLOWED_TRANSITIONS = {
        IdentityStatus.PENDING_VERIFICATION: {IdentityStatus.ACTIVE, IdentityStatus.DEACTIVATED},
        IdentityStatus.ACTIVE: {IdentityStatus.SUSPENDED, IdentityStatus.DEACTIVATED},
        IdentityStatus.SUSPENDED: {IdentityStatus.ACTIVE, IdentityStatus.DEACTIVATED},
        IdentityStatus.DEACTIVATED: {IdentityStatus.ACTIVE},  # reactivation permitted under strict audit
    }

    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = []

    def transition_state(
        self,
        identity: UserIdentity,
        target_status: IdentityStatus,
        actor: str,
        reason: str,
    ) -> UserIdentity:
        current = identity.status
        allowed = self.ALLOWED_TRANSITIONS.get(current, set())

        if target_status not in allowed:
            raise IdentityLifecycleError(
                f"Illegal identity lifecycle transition from '{current.value}' to '{target_status.value}' for {identity.identity_id}."
            )

        identity.status = target_status
        audit_entry = {
            "identity_id": identity.identity_id,
            "previous_status": current.value,
            "new_status": target_status.value,
            "actor": actor,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._audit_log.append(audit_entry)
        return identity

    def get_audit_trail(self, identity_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if identity_id:
            return [e for e in self._audit_log if e["identity_id"] == identity_id]
        return list(self._audit_log)
