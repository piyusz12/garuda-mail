"""
User and Human Identity Ingestion.
Represents user identities from Enterprise IdPs, Directories (LDAP/AD/Okta), and HR systems.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class IdentityStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"


@dataclass
class UserIdentity:
    identity_id: str
    username: str
    email: str
    full_name: str
    department: str
    title: str
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    status: IdentityStatus = IdentityStatus.ACTIVE
    mfa_enabled: bool = True
    mfa_method: str = "FIDO2_WEBAUTHN"
    risk_level: str = "LOW"
    tenant_id: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "department": self.department,
            "title": self.title,
            "groups": self.groups,
            "roles": self.roles,
            "status": self.status.value if isinstance(self.status, IdentityStatus) else self.status,
            "mfa_enabled": self.mfa_enabled,
            "mfa_method": self.mfa_method,
            "risk_level": self.risk_level,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }


class UserIdentityRepository:
    """Manages ingested user identities."""

    def __init__(self):
        self._identities: Dict[str, UserIdentity] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            UserIdentity(
                identity_id="ID-1192",
                username="john.smith",
                email="john.smith@enterprise.org",
                full_name="John Smith",
                department="Security Operations",
                title="Lead SOC Analyst",
                groups=["security-ops", "tier2-analysts", "mta-admins"],
                roles=["SOC_ADMIN", "INCIDENT_RESPONDER"],
                status=IdentityStatus.ACTIVE,
                mfa_enabled=True,
                mfa_method="FIDO2_HARDWARE_KEY",
                risk_level="LOW",
            ),
            UserIdentity(
                identity_id="ID-2044",
                username="alice.chen",
                email="alice.chen@enterprise.org",
                full_name="Alice Chen",
                department="Network Infrastructure",
                title="MTA Systems Engineer",
                groups=["network-engineering", "mta-admins"],
                roles=["INFRA_ADMIN"],
                status=IdentityStatus.ACTIVE,
                mfa_enabled=True,
                mfa_method="TOTP_AUTHENTICATOR",
                risk_level="LOW",
            ),
            UserIdentity(
                identity_id="ID-3088",
                username="bob.contractor",
                email="bcontractor@external-vendor.com",
                full_name="Bob Contractor",
                department="Vendor Operations",
                title="External Mail Migration Specialist",
                groups=["external-vendors"],
                roles=["GUEST_OPERATOR"],
                status=IdentityStatus.ACTIVE,
                mfa_enabled=False,
                mfa_method="NONE",
                risk_level="HIGH",
            ),
            UserIdentity(
                identity_id="ID-SERVICE-MTA",
                username="svc-mta-pipeline",
                email="svc-mta@service.internal",
                full_name="MTA Service Account",
                department="Core Platform",
                title="Service Principal",
                groups=["service-accounts"],
                roles=["SYSTEM_RELAY"],
                status=IdentityStatus.ACTIVE,
                mfa_enabled=True,
                mfa_method="MUTUAL_TLS_CERT",
                risk_level="LOW",
            ),
        ]
        for u in defaults:
            self._identities[u.identity_id] = u

    def get(self, identity_id: str) -> Optional[UserIdentity]:
        return self._identities.get(identity_id)

    def get_by_username(self, username: str) -> Optional[UserIdentity]:
        for u in self._identities.values():
            if u.username == username or u.email == username:
                return u
        return None

    def list_all(self) -> List[UserIdentity]:
        return list(self._identities.values())

    def register(self, identity: UserIdentity) -> None:
        self._identities[identity.identity_id] = identity
