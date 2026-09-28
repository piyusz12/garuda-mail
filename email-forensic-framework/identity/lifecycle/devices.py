"""
Device Fleet Lifecycle Manager.
Tracks device state transitions: REGISTERED -> ENROLLED -> COMPLIANT -> QUARANTINED -> RETIRED.
"""
from typing import Dict, List, Optional, Any
import time

from identity.ingestion.devices import DeviceIdentity, DeviceComplianceStatus


class DeviceLifecycleManager:
    """Manages fleet device enrollment and retirement."""

    def __init__(self):
        self._audit: List[Dict[str, Any]] = []

    def set_device_status(
        self,
        device: DeviceIdentity,
        new_status: DeviceComplianceStatus,
        actor: str,
        reason: str,
    ) -> DeviceIdentity:
        old_status = device.compliance_status
        device.compliance_status = new_status

        self._audit.append({
            "device_id": device.device_id,
            "old_status": old_status.value if isinstance(old_status, DeviceComplianceStatus) else old_status,
            "new_status": new_status.value if isinstance(new_status, DeviceComplianceStatus) else new_status,
            "actor": actor,
            "reason": reason,
            "timestamp": time.time(),
        })
        return device

    def get_audit(self) -> List[Dict[str, Any]]:
        return list(self._audit)
