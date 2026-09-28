"""
Identity Risk Engine.
Aggregates authentication context, device posture, privilege level, behavioral deviation, and historical findings.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from identity.posture.device import DevicePostureState, DevicePostureLevel
from .session import SessionRiskScore, SessionRiskLevel


class IdentityRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class IdentityRiskAssessment:
    identity_id: str
    overall_score: float  # 0.0 to 100.0
    risk_level: IdentityRiskLevel
    contributing_factors: List[str] = field(default_factory=list)
    device_risk_component: float = 0.0
    session_risk_component: float = 0.0
    privilege_component: float = 0.0
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.value if isinstance(self.risk_level, IdentityRiskLevel) else self.risk_level,
            "contributing_factors": self.contributing_factors,
            "device_risk_component": round(self.device_risk_component, 1),
            "session_risk_component": round(self.session_risk_component, 1),
            "privilege_component": round(self.privilege_component, 1),
            "evaluated_at": self.evaluated_at,
        }


class IdentityRiskEngine:
    """Combines posture, session anomalies, and account privilege into holistic identity risk."""

    @staticmethod
    def calculate_risk(
        identity_id: str,
        device_posture: Optional[DevicePostureState] = None,
        session_risk: Optional[SessionRiskScore] = None,
        is_privileged: bool = False,
        historical_findings_count: int = 0,
    ) -> IdentityRiskAssessment:
        score = 10.0
        factors = []

        dev_comp = 0.0
        if device_posture:
            if device_posture.posture_level == DevicePostureLevel.NONCOMPLIANT:
                dev_comp = 35.0
                factors.append(f"Associated device '{device_posture.device_id}' is non-compliant/unmanaged")
            elif device_posture.posture_level == DevicePostureLevel.DEGRADED:
                dev_comp = 20.0
                factors.append(f"Associated device '{device_posture.device_id}' posture degraded")

        sess_comp = 0.0
        if session_risk:
            if session_risk.risk_level == SessionRiskLevel.CRITICAL:
                sess_comp = 40.0
                factors.append(f"Active session risk CRITICAL: {', '.join(session_risk.factors)}")
            elif session_risk.risk_level == SessionRiskLevel.HIGH:
                sess_comp = 25.0
                factors.append(f"Active session risk HIGH: {', '.join(session_risk.factors)}")
            elif session_risk.risk_level == SessionRiskLevel.MEDIUM:
                sess_comp = 15.0
                factors.append("Active session risk MEDIUM")

        priv_comp = 0.0
        if is_privileged:
            priv_comp = 15.0
            factors.append("Identity possesses administrative/privileged entitlements")

        if historical_findings_count > 0:
            hist_boost = min(20.0, historical_findings_count * 5.0)
            factors.append(f"{historical_findings_count} previous security findings linked to identity")
            score += hist_boost

        total = min(100.0, score + dev_comp + sess_comp + priv_comp)

        if total >= 80.0:
            level = IdentityRiskLevel.CRITICAL
        elif total >= 60.0:
            level = IdentityRiskLevel.HIGH
        elif total >= 40.0:
            level = IdentityRiskLevel.ELEVATED
        elif total >= 25.0:
            level = IdentityRiskLevel.MEDIUM
        else:
            level = IdentityRiskLevel.LOW

        return IdentityRiskAssessment(
            identity_id=identity_id,
            overall_score=total,
            risk_level=level,
            contributing_factors=factors,
            device_risk_component=dev_comp,
            session_risk_component=sess_comp,
            privilege_component=priv_comp,
        )
