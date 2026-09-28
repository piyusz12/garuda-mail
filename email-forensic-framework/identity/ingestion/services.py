"""
Service Identity Ingestion & Resource Classification.
Represents backend services, APIs, mail transfer agents, and data storage systems.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class ResourceClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    CRITICAL = "CRITICAL"


@dataclass
class ServiceIdentity:
    service_id: str
    service_name: str
    owner_identity_id: str
    environment: str  # production, staging, range
    namespace: str
    classification: ResourceClassification
    certificate_id: Optional[str]
    port: int
    protocol: str  # smtp, https, mtls, ldaps
    endpoint: str
    trust_level: str = "HIGH"
    allowed_source_groups: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_id": self.service_id,
            "service_name": self.service_name,
            "owner_identity_id": self.owner_identity_id,
            "environment": self.environment,
            "namespace": self.namespace,
            "classification": self.classification.value if isinstance(self.classification, ResourceClassification) else self.classification,
            "certificate_id": self.certificate_id,
            "port": self.port,
            "protocol": self.protocol,
            "endpoint": self.endpoint,
            "trust_level": self.trust_level,
            "allowed_source_groups": self.allowed_source_groups,
        }


class ServiceIdentityRepository:
    """Registry of enterprise service identities."""

    def __init__(self):
        self._services: Dict[str, ServiceIdentity] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            ServiceIdentity(
                service_id="MTA-07",
                service_name="Primary Edge Mail Gateway",
                owner_identity_id="ID-2044",
                environment="production",
                namespace="mail-core",
                classification=ResourceClassification.CRITICAL,
                certificate_id="CERT-2026-PRIMARY",
                port=25,
                protocol="smtp",
                endpoint="mta-07.corp.local:25",
                trust_level="HIGH",
                allowed_source_groups=["security-ops", "mta-admins", "service-accounts"],
            ),
            ServiceIdentity(
                service_id="MTA-02",
                service_name="Internal Mail Relay 02",
                owner_identity_id="ID-2044",
                environment="production",
                namespace="mail-core",
                classification=ResourceClassification.SENSITIVE,
                certificate_id="CERT-INTERNAL-RELAY",
                port=587,
                protocol="smtp",
                endpoint="mta-02.corp.local:587",
                trust_level="HIGH",
                allowed_source_groups=["mta-admins", "service-accounts"],
            ),
            ServiceIdentity(
                service_id="FORENSIC-API",
                service_name="Forensic Investigation Console API",
                owner_identity_id="ID-1192",
                environment="production",
                namespace="soc-ops",
                classification=ResourceClassification.CRITICAL,
                certificate_id="CERT-FORENSIC-API",
                port=8443,
                protocol="https",
                endpoint="forensic-api.sec.local:8443",
                trust_level="HIGH",
                allowed_source_groups=["security-ops"],
            ),
            ServiceIdentity(
                service_id="EVIDENCE-VAULT",
                service_name="Tamper-Evident Evidence Store",
                owner_identity_id="ID-1192",
                environment="production",
                namespace="soc-ops",
                classification=ResourceClassification.CRITICAL,
                certificate_id="CERT-VAULT-MTLS",
                port=9443,
                protocol="mtls",
                endpoint="evidence-vault.sec.local:9443",
                trust_level="HIGH",
                allowed_source_groups=["security-ops"],
            ),
            ServiceIdentity(
                service_id="PUBLIC-WEBMAIL",
                service_name="Employee Webmail Portal",
                owner_identity_id="ID-2044",
                environment="production",
                namespace="mail-front",
                classification=ResourceClassification.INTERNAL,
                certificate_id="CERT-WEBMAIL",
                port=443,
                protocol="https",
                endpoint="mail.enterprise.org:443",
                trust_level="MEDIUM",
                allowed_source_groups=["all-employees"],
            ),
        ]
        for s in defaults:
            self._services[s.service_id] = s

    def get(self, service_id: str) -> Optional[ServiceIdentity]:
        return self._services.get(service_id)

    def list_all(self) -> List[ServiceIdentity]:
        return list(self._services.values())

    def register(self, service: ServiceIdentity) -> None:
        self._services[service.service_id] = service
