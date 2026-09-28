"""
Device Posture Assessment.
Evaluates host management, disk encryption, EDR agent health, OS patching, and certificate validity.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class DevicePostureLevel(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    NONCOMPLIANT = "NONCOMPLIANT"


@dataclass
class DevicePostureState:
    device_id: str
    managed: bool
    disk_encrypted: bool
    edr_active: bool
    os_patched: bool
    certificate_valid: bool
    posture_score: float  # 0.0 to 1.0
    posture_level: DevicePostureLevel
    signals: Dict[str, Any] = field(default_factory=dict)
    assessed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "managed": self.managed,
            "disk_encrypted": self.disk_encrypted,
            "edr_active": self.edr_active,
            "os_patched": self.os_patched,
            "certificate_valid": self.certificate_valid,
            "posture_score": round(self.posture_score, 2),
            "posture_level": self.posture_level.value if isinstance(self.posture_level, DevicePostureLevel) else self.posture_level,
            "signals": self.signals,
            "assessed_at": self.assessed_at,
        }


class DevicePostureEvaluator:
    """Calculates multidimensional device posture scores."""

    @staticmethod
    def evaluate(
        device_id: str,
        managed: bool,
        disk_encrypted: bool = True,
        edr_active: bool = True,
        os_patched: bool = True,
        certificate_valid: bool = True,
        custom_signals: Optional[Dict[str, Any]] = None,
    ) -> DevicePostureState:
        score = 0.0
        signals = custom_signals or {}

        if managed: score += 0.35
        if disk_encrypted: score += 0.20
        if edr_active: score += 0.20
        if os_patched: score += 0.15
        if certificate_valid: score += 0.10

        if not managed:
            # Unmanaged devices immediately cap at non-compliant / low score
            level = DevicePostureLevel.NONCOMPLIANT
        elif score >= 0.85:
            level = DevicePostureLevel.HEALTHY
        elif score >= 0.50:
            level = DevicePostureLevel.DEGRADED
        else:
            level = DevicePostureLevel.NONCOMPLIANT

        return DevicePostureState(
            device_id=device_id,
            managed=managed,
            disk_encrypted=disk_encrypted,
            edr_active=edr_active,
            os_patched=os_patched,
            certificate_valid=certificate_valid,
            posture_score=score,
            posture_level=level,
            signals=signals,
        )
