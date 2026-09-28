"""
Cyber Range Environment Models.
Defines isolated defensive test ranges, simulated assets, sensor stacks, and shadow mode.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid
import time


class IsolationLevel(str, Enum):
    AIRGAPPED = "AIRGAPPED"
    VIRTUAL_VPC = "VIRTUAL_VPC"
    CONTAINER_SANDBOX = "CONTAINER_SANDBOX"
    SHADOW_MODE = "SHADOW_MODE"


class RangeStatus(str, Enum):
    IDLE = "IDLE"
    RESERVED = "RESERVED"
    ACTIVE = "ACTIVE"
    TEARDOWN = "TEARDOWN"
    MAINTENANCE = "MAINTENANCE"


@dataclass
class RangeAsset:
    asset_id: str
    hostname: str
    ip_address: str
    role: str  # MTA_EDGE, INTERNAL_RELAY, AUTH_SERVICE, STORAGE, CLIENT_PROBE
    operating_system: str
    installed_sensors: List[str]
    is_approved_target: bool = True
    active_services: List[str] = field(default_factory=lambda: ["smtp", "tls"])
    state_snapshot: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "role": self.role,
            "operating_system": self.operating_system,
            "installed_sensors": self.installed_sensors,
            "is_approved_target": self.is_approved_target,
            "active_services": self.active_services,
        }


@dataclass
class RangeEnvironment:
    range_id: str
    name: str
    isolation_level: IsolationLevel
    status: RangeStatus = RangeStatus.IDLE
    subnet_cidr: str = "10.200.0.0/24"
    assets: Dict[str, RangeAsset] = field(default_factory=dict)
    sensor_stack: List[str] = field(default_factory=lambda: ["passive_pcap_sensor", "tls_fingerprint_sensor", "cert_validator_sensor"])
    active_campaign_id: Optional[str] = None
    active_scenario_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_asset(self, asset: RangeAsset) -> None:
        self.assets[asset.asset_id] = asset

    def get_asset(self, asset_id: str) -> Optional[RangeAsset]:
        return self.assets.get(asset_id)

    def is_asset_approved(self, asset_id: str) -> bool:
        asset = self.assets.get(asset_id)
        return bool(asset and asset.is_approved_target)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "range_id": self.range_id,
            "name": self.name,
            "isolation_level": self.isolation_level.value if isinstance(self.isolation_level, IsolationLevel) else self.isolation_level,
            "status": self.status.value if isinstance(self.status, RangeStatus) else self.status,
            "subnet_cidr": self.subnet_cidr,
            "assets": {k: v.to_dict() for k, v in self.assets.items()},
            "sensor_stack": self.sensor_stack,
            "active_campaign_id": self.active_campaign_id,
            "active_scenario_id": self.active_scenario_id,
            "created_at": self.created_at,
        }
