"""
Session Risk Evaluation Engine.
Evaluates in-flight session properties: anomalous destinations, rare JA4s, certificate changes, and timing anomalies.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from .behavior import BehavioralAnalyticsEngine


class SessionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SessionRiskScore:
    session_id: str
    risk_score: float  # 0.0 to 100.0
    risk_level: SessionRiskLevel
    factors: List[str] = field(default_factory=list)
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level.value if isinstance(self.risk_level, SessionRiskLevel) else self.risk_level,
            "factors": self.factors,
            "evaluated_at": self.evaluated_at,
        }


class SessionRiskEngine:
    """Calculates risk for individual active communication sessions."""

    def __init__(self, behavioral_engine: Optional[BehavioralAnalyticsEngine] = None):
        self.behavioral_engine = behavioral_engine or BehavioralAnalyticsEngine()

    def evaluate_session(
        self,
        session_id: str,
        identity_id: str,
        device_id: str,
        service_id: str,
        ja4: Optional[str] = None,
        destination_ip: str = "10.200.1.7",
        destination_port: int = 25,
        tls_version: str = "TLS 1.3",
        cert_valid: bool = True,
        timestamp: Optional[float] = None,
    ) -> SessionRiskScore:
        ts = timestamp or time.time()
        score = 10.0
        factors = []

        baseline = self.behavioral_engine.get_baseline(identity_id)

        # 1. Device check
        if baseline.is_new_device(device_id):
            score += 25.0
            factors.append(f"New device '{device_id}' never previously associated with identity")

        # 2. Service check
        if baseline.is_new_service(service_id):
            score += 20.0
            factors.append(f"New service target '{service_id}' for identity")

        # 3. JA4 Fingerprint check
        if ja4 and baseline.is_rare_ja4(ja4):
            score += 25.0
            factors.append(f"Anomalous JA4 fingerprint: {ja4}")

        # 4. Protocol & Crypto checks
        if tls_version in ("TLS 1.0", "TLS 1.1", "SSLv3"):
            score += 35.0
            factors.append(f"Legacy insecure protocol negotiated: {tls_version}")

        if not cert_valid:
            score += 40.0
            factors.append("Untrusted or invalid X.509 certificate presentation")

        # 5. Timing check (UTC hour)
        current_hour = time.gmtime(ts).tm_hour
        if baseline.is_unusual_hour(current_hour):
            score += 15.0
            factors.append(f"Session initiated at unusual hour ({current_hour}:00 UTC)")

        score = min(100.0, score)

        if score >= 75.0:
            level = SessionRiskLevel.CRITICAL
        elif score >= 50.0:
            level = SessionRiskLevel.HIGH
        elif score >= 30.0:
            level = SessionRiskLevel.MEDIUM
        else:
            level = SessionRiskLevel.LOW

        return SessionRiskScore(
            session_id=session_id,
            risk_score=score,
            risk_level=level,
            factors=factors,
            evaluated_at=ts,
        )
