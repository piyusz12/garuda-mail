"""
Cyber Range Manager.
Orchestrates virtual test ranges, asset deployment, isolation validation, and snapshots.
"""
from typing import Dict, List, Optional, Any
import time
from .environments import RangeEnvironment, RangeAsset, IsolationLevel, RangeStatus
from .isolation import IsolationController, RangeIsolationViolation
from .teardown import RangeTeardownController


class RangeManager:
    """Central registry and life-cycle manager for defensive validation cyber ranges."""

    def __init__(self):
        self._ranges: Dict[str, RangeEnvironment] = {}
        self.isolation_controller = IsolationController()
        self.teardown_controller = RangeTeardownController()
        self._initialize_default_ranges()

    def _initialize_default_ranges(self):
        # Range-A: Primary Cyber Range for Network & Certificate Testing
        range_a = RangeEnvironment(
            range_id="RANGE-A",
            name="Primary Mail Core Validation Range",
            isolation_level=IsolationLevel.CONTAINER_SANDBOX,
            subnet_cidr="10.200.1.0/24",
            sensor_stack=["passive_pcap_sensor", "tls_fingerprint_sensor", "cert_validator_sensor"],
        )
        range_a.add_asset(RangeAsset(
            asset_id="MTA-07",
            hostname="mta-edge-07.range.local",
            ip_address="10.200.1.7",
            role="MTA_EDGE",
            operating_system="Linux-Hardened-6.8",
            installed_sensors=["tls_passive_tap", "zeek_agent", "ja4_monitor"],
            is_approved_target=True,
            active_services=["smtp", "starttls", "tls_1_3"],
            state_snapshot={"cert_serial": "4A:91:BC:02", "tls_version": "TLS 1.3"},
        ))
        range_a.add_asset(RangeAsset(
            asset_id="MTA-02",
            hostname="mta-relay-02.range.local",
            ip_address="10.200.1.2",
            role="INTERNAL_RELAY",
            operating_system="Linux-Hardened-6.8",
            installed_sensors=["tls_passive_tap", "ja4_monitor"],
            is_approved_target=True,
            active_services=["smtp", "tls_1_3"],
            state_snapshot={"cert_serial": "99:11:AB:FF", "tls_version": "TLS 1.3"},
        ))

        # Range-B: Cryptographic Agility & PQC Range
        range_b = RangeEnvironment(
            range_id="RANGE-B",
            name="Cryptographic Agility & PQC Range",
            isolation_level=IsolationLevel.VIRTUAL_VPC,
            subnet_cidr="10.200.2.0/24",
            sensor_stack=["pqc_telemetry_sensor", "tls_crypto_inspector"],
        )
        range_b.add_asset(RangeAsset(
            asset_id="MTA-PQC-01",
            hostname="mta-pqc-01.range.local",
            ip_address="10.200.2.10",
            role="MTA_EDGE",
            operating_system="Linux-Hardened-6.8",
            installed_sensors=["pqc_monitor", "tls_passive_tap"],
            is_approved_target=True,
            active_services=["smtp", "pqc_hybrid_kem", "tls_1_3"],
            state_snapshot={"pqc_mode": "ML-KEM-768", "tls_version": "TLS 1.3"},
        ))

        # Range-Staging: Production Shadow Validation Range
        range_staging = RangeEnvironment(
            range_id="RANGE-STAGING",
            name="Production Shadow Telemetry Range",
            isolation_level=IsolationLevel.SHADOW_MODE,
            subnet_cidr="10.200.99.0/24",
            sensor_stack=["production_mirror_tap", "shadow_evaluator"],
        )
        range_staging.add_asset(RangeAsset(
            asset_id="MTA-PROD-MIRROR",
            hostname="mta-mirror.staging.local",
            ip_address="10.200.99.5",
            role="SHADOW_REPLICA",
            operating_system="Linux-Hardened-6.8",
            installed_sensors=["production_mirror_tap"],
            is_approved_target=True,
            active_services=["smtp_shadow_mirror"],
        ))

        self._ranges[range_a.range_id] = range_a
        self._ranges[range_b.range_id] = range_b
        self._ranges[range_staging.range_id] = range_staging

    def get_range(self, range_id: str) -> Optional[RangeEnvironment]:
        return self._ranges.get(range_id)

    def list_ranges(self) -> List[RangeEnvironment]:
        return list(self._ranges.values())

    def register_range(self, range_env: RangeEnvironment) -> None:
        self._ranges[range_env.range_id] = range_env

    def reserve_range(self, range_id: str, campaign_id: Optional[str] = None, scenario_id: Optional[str] = None) -> RangeEnvironment:
        range_env = self._ranges.get(range_id)
        if not range_env:
            raise ValueError(f"Range {range_id} does not exist.")
        if range_env.status == RangeStatus.ACTIVE and range_env.active_scenario_id != scenario_id:
            raise ValueError(f"Range {range_id} is currently busy running scenario {range_env.active_scenario_id}.")

        range_env.status = RangeStatus.ACTIVE
        range_env.active_campaign_id = campaign_id
        range_env.active_scenario_id = scenario_id
        return range_env

    def release_range(self, range_id: str) -> None:
        range_env = self._ranges.get(range_id)
        if range_env:
            self.teardown_controller.teardown_range(range_env)
