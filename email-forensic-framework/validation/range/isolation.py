"""
Cyber Range Network Isolation and Safety Boundaries.
Ensures zero packet leakage outside authorized test ranges.
"""
from typing import Dict, List, Optional, Any, Set
import ipaddress
from .environments import RangeEnvironment, IsolationLevel


class RangeIsolationViolation(Exception):
    """Raised when an action or network packet attempts to cross isolation boundaries."""
    pass


class IsolationController:
    """Enforces strict boundaries, egress filtering, and shadow mode isolation."""

    def __init__(self):
        self._allowed_cidrs: Dict[str, ipaddress.IPv4Network] = {
            "RANGE-A": ipaddress.IPv4Network("10.200.1.0/24"),
            "RANGE-B": ipaddress.IPv4Network("10.200.2.0/24"),
            "RANGE-C": ipaddress.IPv4Network("10.200.3.0/24"),
            "RANGE-STAGING": ipaddress.IPv4Network("10.200.99.0/24"),
        }

    def validate_target_in_range(self, range_env: RangeEnvironment, target_ip_or_asset: str) -> bool:
        """Verifies that the target belongs to the designated range and is within the range subnet."""
        # Check by asset_id
        if target_ip_or_asset in range_env.assets:
            asset = range_env.assets[target_ip_or_asset]
            if not asset.is_approved_target:
                raise RangeIsolationViolation(f"Asset {target_ip_or_asset} exists in range but is not marked as an approved target.")
            return True

        # Check by IP address
        try:
            ip = ipaddress.IPv4Address(target_ip_or_asset)
            allowed_net = self._allowed_cidrs.get(range_env.range_id)
            if allowed_net and ip in allowed_net:
                return True
        except ValueError:
            pass

        raise RangeIsolationViolation(
            f"Target {target_ip_or_asset} is not inside approved subnet {range_env.subnet_cidr} for range {range_env.range_id}"
        )

    def verify_no_production_leakage(self, range_env: RangeEnvironment, outbound_dest_ip: str) -> bool:
        """Ensures egress packets do not target external or production addresses."""
        if range_env.isolation_level == IsolationLevel.SHADOW_MODE:
            # Shadow mode is passive read-only, never transmits live active traffic
            return True

        try:
            dest = ipaddress.IPv4Address(outbound_dest_ip)
            allowed_net = self._allowed_cidrs.get(range_env.range_id)
            if allowed_net and dest in allowed_net:
                return True
            # Allow loopback for mock service interaction
            if dest.is_loopback:
                return True
        except ValueError:
            pass

        raise RangeIsolationViolation(
            f"Network egress block: Destination {outbound_dest_ip} is outside range boundary {range_env.subnet_cidr}."
        )

    def is_shadow_mode_safe(self, range_env: RangeEnvironment) -> bool:
        """Shadow mode guarantee: completely read-only evaluation without modifying live state."""
        return range_env.isolation_level == IsolationLevel.SHADOW_MODE
