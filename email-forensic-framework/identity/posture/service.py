"""
Service Posture Assessment.
Evaluates mTLS configuration, certificate expiration, cryptographic agility, and compliance.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class ServicePostureState:
    service_id: str
    mtls_enforced: bool
    cert_valid: bool
    cert_expiry_days: int
    pqc_compliant: bool
    posture_score: float
    is_compliant: bool
    assessed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_id": self.service_id,
            "mtls_enforced": self.mtls_enforced,
            "cert_valid": self.cert_valid,
            "cert_expiry_days": self.cert_expiry_days,
            "pqc_compliant": self.pqc_compliant,
            "posture_score": round(self.posture_score, 2),
            "is_compliant": self.is_compliant,
        }


class ServicePostureEvaluator:
    """Calculates service posture and crypto compliance."""

    @staticmethod
    def evaluate(
        service_id: str,
        mtls_enforced: bool = True,
        cert_valid: bool = True,
        cert_expiry_days: int = 180,
        pqc_compliant: bool = True,
    ) -> ServicePostureState:
        score = 0.0
        if mtls_enforced: score += 0.40
        if cert_valid: score += 0.30
        if cert_expiry_days > 30: score += 0.15
        if pqc_compliant: score += 0.15

        is_compliant = cert_valid and (cert_expiry_days > 0)

        return ServicePostureState(
            service_id=service_id,
            mtls_enforced=mtls_enforced,
            cert_valid=cert_valid,
            cert_expiry_days=cert_expiry_days,
            pqc_compliant=pqc_compliant,
            posture_score=score,
            is_compliant=is_compliant,
        )
