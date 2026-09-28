"""
Normalized Identity Entities and Binding Models.
Connects users, devices, services, workloads, certificates, and sessions into unified entities.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class CertificateIdentityBinding:
    """Component 7: Certificate-to-Identity Binding."""
    certificate_id: str
    identity_id: str  # User, Device, or Service ID
    binding_type: str  # USER_CLIENT_AUTH, DEVICE_TRUST_CERT, SERVICE_TLS_CERT
    valid_from: str
    valid_to: str
    is_active: bool = True
    binding_confidence: float = 0.98
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "identity_id": self.identity_id,
            "binding_type": self.binding_type,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "is_active": self.is_active,
            "binding_confidence": self.binding_confidence,
        }


@dataclass
class SessionIdentityBinding:
    """Component 8: Session-to-Identity Binding."""
    session_id: str
    source_identity_id: str
    source_device_id: str
    destination_service_id: str
    certificate_id: Optional[str] = None
    ja4: Optional[str] = None
    tls_version: Optional[str] = None
    source_ip: str = "10.200.1.44"
    destination_ip: str = "10.200.1.7"
    destination_port: int = 25
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_identity_id": self.source_identity_id,
            "source_device_id": self.source_device_id,
            "destination_service_id": self.destination_service_id,
            "certificate_id": self.certificate_id,
            "ja4": self.ja4,
            "tls_version": self.tls_version,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "created_at": self.created_at,
        }
