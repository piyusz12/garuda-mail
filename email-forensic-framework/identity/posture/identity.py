"""
Identity Posture Assessment.
Evaluates MFA enforcement, credential hygiene, password age, and recent authentication failures.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class IdentityPostureLevel(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    AT_RISK = "AT_RISK"


@dataclass
class IdentityPostureState:
    identity_id: str
    mfa_enforced: bool
    password_age_days: int
    failed_logins_24h: int
    privileged: bool
    posture_score: float
    posture_level: IdentityPostureLevel
    assessed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "mfa_enforced": self.mfa_enforced,
            "password_age_days": self.password_age_days,
            "failed_logins_24h": self.failed_logins_24h,
            "privileged": self.privileged,
            "posture_score": round(self.posture_score, 2),
            "posture_level": self.posture_level.value if isinstance(self.posture_level, IdentityPostureLevel) else self.posture_level,
        }


class IdentityPostureEvaluator:
    """Calculates identity posture state."""

    @staticmethod
    def evaluate(
        identity_id: str,
        mfa_enforced: bool = True,
        password_age_days: int = 30,
        failed_logins_24h: int = 0,
        privileged: bool = False,
    ) -> IdentityPostureState:
        score = 1.0

        if not mfa_enforced:
            score -= 0.40
        if password_age_days > 90:
            score -= 0.15
        if failed_logins_24h > 3:
            score -= 0.30
        if privileged and not mfa_enforced:
            score -= 0.20

        score = max(0.0, score)

        if score >= 0.80:
            level = IdentityPostureLevel.HEALTHY
        elif score >= 0.50:
            level = IdentityPostureLevel.DEGRADED
        else:
            level = IdentityPostureLevel.AT_RISK

        return IdentityPostureState(
            identity_id=identity_id,
            mfa_enforced=mfa_enforced,
            password_age_days=password_age_days,
            failed_logins_24h=failed_logins_24h,
            privileged=privileged,
            posture_score=score,
            posture_level=level,
        )
