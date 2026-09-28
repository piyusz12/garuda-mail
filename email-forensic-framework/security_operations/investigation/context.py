"""
Phase 25 — Investigation Context & Maintenance Awareness
Stores multi-source asset, certificate, change management, and maintenance window context.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import time


@dataclass
class AssetContext:
    asset_id: str
    hostname: str
    ip_address: str
    criticality: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    environment: str = "production"
    owner: str = "secops@example.com"
    services: List[str] = field(default_factory=lambda: ["smtp", "imap", "mta"])
    dependencies: List[str] = field(default_factory=list)


@dataclass
class MaintenanceWindow:
    window_id: str
    asset_id: str
    start_time: float
    end_time: float
    approved_by: str
    change_ticket_id: str
    description: str


class MaintenanceWindowChecker:
    """Checks whether an event timestamp falls within an approved maintenance window."""

    def __init__(self):
        self._windows: List[MaintenanceWindow] = []

    def register_window(
        self,
        asset_id: str,
        start_time: float,
        end_time: float,
        approved_by: str,
        change_ticket_id: str,
        description: str = "",
    ) -> MaintenanceWindow:
        win = MaintenanceWindow(
            window_id=f"MW-{len(self._windows)+1:03d}",
            asset_id=asset_id,
            start_time=start_time,
            end_time=end_time,
            approved_by=approved_by,
            change_ticket_id=change_ticket_id,
            description=description,
        )
        self._windows.append(win)
        return win

    def is_in_maintenance(self, asset_id: str, timestamp: float) -> Tuple[bool, Optional[MaintenanceWindow]]:
        for w in self._windows:
            if (w.asset_id == asset_id or w.asset_id == "*") and (w.start_time <= timestamp <= w.end_time):
                return True, w
        return False, None
