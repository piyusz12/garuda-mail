"""
Access Request Context & Trust Context Models.
Represents dynamic trust scores across identity, device, session, and service dimensions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import json
import time


@dataclass
class TrustContext:
    """Component 11: Explicit multidimensional trust representation."""
    identity_trust: float  # 0.0 to 1.0
    device_trust: float    # 0.0 to 1.0
    session_trust: float   # 0.0 to 1.0
    service_trust: float   # 0.0 to 1.0
    overall_trust_score: float  # 0.0 to 1.0
    trust_tier: str  # HIGH, ELEVATED, STANDARD, UNTRUSTED
    signals: Dict[str, Any] = field(default_factory=dict)
    calculated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_trust": round(self.identity_trust, 2),
            "device_trust": round(self.device_trust, 2),
            "session_trust": round(self.session_trust, 2),
            "service_trust": round(self.service_trust, 2),
            "overall_trust_score": round(self.overall_trust_score, 2),
            "trust_tier": self.trust_tier,
            "signals": self.signals,
            "calculated_at": self.calculated_at,
        }


@dataclass
class AccessRequestContext:
    """Dynamic context accompanying each access request."""
    subject_id: str
    subject_group: str
    subject_role: str
    device_id: str
    device_managed: bool
    device_posture: str  # HEALTHY, DEGRADED, NONCOMPLIANT
    resource_id: str
    resource_classification: str  # PUBLIC, INTERNAL, SENSITIVE, CRITICAL
    action: str  # read, write, administer, relay
    session_id: Optional[str] = None
    session_risk: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    ja4: Optional[str] = None
    tls_version: str = "TLS 1.3"
    client_ip: str = "10.200.1.44"
    time_utc_hour: int = 14
    trust_context: Optional[TrustContext] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_evaluation_dict(self) -> Dict[str, Any]:
        """Flattens context for policy condition matching."""
        d = {
            "subject.id": self.subject_id,
            "subject.group": self.subject_group,
            "subject.role": self.subject_role,
            "device.id": self.device_id,
            "device.managed": self.device_managed,
            "device.posture": self.device_posture,
            "resource.id": self.resource_id,
            "resource.classification": self.resource_classification,
            "action": self.action,
            "session.id": self.session_id,
            "session.risk": self.session_risk,
            "session.ja4": self.ja4,
            "session.tls_version": self.tls_version,
            "client_ip": self.client_ip,
            "session.time_utc_hour": self.time_utc_hour,
        }
        if self.trust_context:
            d["trust.overall"] = self.trust_context.overall_trust_score
            d["trust.tier"] = self.trust_context.trust_tier
        return d

    def compute_cache_key(self, policy_version: str = "1.0.0") -> str:
        blob = f"{self.subject_id}:{self.device_id}:{self.resource_id}:{self.action}:{self.device_managed}:{self.device_posture}:{self.session_risk}:{policy_version}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
