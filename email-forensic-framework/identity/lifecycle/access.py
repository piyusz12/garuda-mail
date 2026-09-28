"""
Access Entitlement Lifecycle Manager.
Tracks PROVISION -> USE -> MONITOR -> REVIEW -> MODIFY -> EXPIRE -> REVOKE.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class AccessState(str, Enum):
    PROVISIONED = "PROVISIONED"
    ACTIVE = "ACTIVE"
    FLAGGED_STALE = "FLAGGED_STALE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class AccessGrant:
    grant_id: str
    identity_id: str
    resource_id: str
    action: str  # read, write, administer, relay
    state: AccessState = AccessState.PROVISIONED
    granted_by: str = "identity_admin"
    valid_from: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used: Optional[float] = None
    reason: str = "Standard role entitlement"

    def is_valid_now(self) -> bool:
        now = time.time()
        if self.state not in (AccessState.PROVISIONED, AccessState.ACTIVE):
            return False
        if self.expires_at is not None and now > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "identity_id": self.identity_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "state": self.state.value if isinstance(self.state, AccessState) else self.state,
            "granted_by": self.granted_by,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "last_used": self.last_used,
            "reason": self.reason,
        }


class AccessLifecycleManager:
    """Manages access entitlements, usage tracking, and automatic expiration."""

    def __init__(self):
        self._grants: Dict[str, AccessGrant] = {}
        self._load_defaults()

    def _load_defaults(self):
        g1 = AccessGrant(
            grant_id="GRANT-001",
            identity_id="ID-1192",
            resource_id="FORENSIC-API",
            action="administer",
            state=AccessState.ACTIVE,
            reason="SOC Lead Console Administration",
        )
        g2 = AccessGrant(
            grant_id="GRANT-002",
            identity_id="ID-1192",
            resource_id="MTA-07",
            action="read",
            state=AccessState.ACTIVE,
            reason="Forensic Traffic Analysis",
        )
        g3 = AccessGrant(
            grant_id="GRANT-003",
            identity_id="ID-2044",
            resource_id="MTA-07",
            action="administer",
            state=AccessState.ACTIVE,
            reason="MTA Operations Lead",
        )
        for g in [g1, g2, g3]:
            self._grants[g.grant_id] = g

    def grant_access(
        self,
        identity_id: str,
        resource_id: str,
        action: str,
        granted_by: str,
        duration_seconds: Optional[float] = None,
        reason: str = "Access request approved",
    ) -> AccessGrant:
        gid = f"GRANT-{uuid.uuid4().hex[:6].upper()}"
        now = time.time()
        expires = now + duration_seconds if duration_seconds else None

        grant = AccessGrant(
            grant_id=gid,
            identity_id=identity_id,
            resource_id=resource_id,
            action=action,
            state=AccessState.ACTIVE,
            granted_by=granted_by,
            valid_from=now,
            expires_at=expires,
            reason=reason,
        )
        self._grants[gid] = grant
        return grant

    def revoke_grant(self, grant_id: str, actor: str, reason: str) -> AccessGrant:
        grant = self._grants.get(grant_id)
        if not grant:
            raise KeyError(f"Grant {grant_id} not found.")
        grant.state = AccessState.REVOKED
        return grant

    revoke_access = revoke_grant

    def get_grant(self, grant_id: str) -> Optional[AccessGrant]:
        return self._grants.get(grant_id)

    def list_grants(self, identity_id: Optional[str] = None) -> List[AccessGrant]:
        grants = list(self._grants.values())
        if identity_id:
            grants = [g for g in grants if g.identity_id == identity_id]
        return grants
