"""
Behavioral Identity Analytics & Historical Baselines.
Models baseline behavioral profiles for identities (usual devices, services, hours, JA4 fingerprints).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import time


@dataclass
class IdentityBehaviorBaseline:
    identity_id: str
    known_devices: Set[str] = field(default_factory=set)
    known_services: Set[str] = field(default_factory=set)
    known_ja4_fingerprints: Set[str] = field(default_factory=set)
    typical_active_hours_utc: Set[int] = field(default_factory=lambda: set(range(8, 20)))  # 08:00 - 19:59
    typical_admin_actions_daily: float = 3.0
    last_updated: float = field(default_factory=time.time)

    def is_new_device(self, device_id: str) -> bool:
        return device_id not in self.known_devices

    def is_new_service(self, service_id: str) -> bool:
        return service_id not in self.known_services

    def is_rare_ja4(self, ja4: Optional[str]) -> bool:
        if not ja4:
            return False
        return ja4 not in self.known_ja4_fingerprints

    def is_unusual_hour(self, hour_utc: int) -> bool:
        return hour_utc not in self.typical_active_hours_utc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "known_devices": list(self.known_devices),
            "known_services": list(self.known_services),
            "known_ja4_fingerprints": list(self.known_ja4_fingerprints),
            "typical_active_hours_utc": sorted(list(self.typical_active_hours_utc)),
            "typical_admin_actions_daily": self.typical_admin_actions_daily,
        }


class BehavioralAnalyticsEngine:
    """Maintains baselines and calculates deviation scores for identities."""

    def __init__(self):
        self._baselines: Dict[str, IdentityBehaviorBaseline] = {}
        self._load_seed_baselines()

    def _load_seed_baselines(self):
        b1 = IdentityBehaviorBaseline(
            identity_id="ID-1192",
            known_devices={"DEVICE-44"},
            known_services={"MTA-07", "FORENSIC-API", "EVIDENCE-VAULT"},
            known_ja4_fingerprints={"t13d1516h2_8daaf6152771_b0da82dd1654", "t13d030800_standard_corp"},
            typical_active_hours_utc=set(range(7, 21)),
        )
        b2 = IdentityBehaviorBaseline(
            identity_id="ID-2044",
            known_devices={"DEVICE-91"},
            known_services={"MTA-07", "MTA-02"},
            known_ja4_fingerprints={"t13d030800_standard_corp"},
            typical_active_hours_utc=set(range(8, 19)),
        )
        self._baselines[b1.identity_id] = b1
        self._baselines[b2.identity_id] = b2

    def get_baseline(self, identity_id: str) -> IdentityBehaviorBaseline:
        if identity_id not in self._baselines:
            # Default empty baseline
            self._baselines[identity_id] = IdentityBehaviorBaseline(identity_id=identity_id)
        return self._baselines[identity_id]

    def set_baseline(self, baseline: IdentityBehaviorBaseline):
        self._baselines[baseline.identity_id] = baseline

    save_baseline = set_baseline

    def record_activity(self, identity_id: str, device_id: str, service_id: str, ja4: Optional[str] = None):
        b = self.get_baseline(identity_id)
        b.known_devices.add(device_id)
        b.known_services.add(service_id)
        if ja4:
            b.known_ja4_fingerprints.add(ja4)
        b.last_updated = time.time()
