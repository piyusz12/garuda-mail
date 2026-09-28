"""
Cyber Range Lifecycle, Snapshot & Teardown Controller.
Enforces rollback availability and state restoration after each scenario execution.
"""
from typing import Dict, List, Optional, Any
import copy
import time
from .environments import RangeEnvironment, RangeStatus


class RangeTeardownError(Exception):
    pass


class RangeTeardownController:
    """Manages baseline snapshots and safe state rollback for cyber range assets."""

    def __init__(self):
        self._snapshots: Dict[str, Dict[str, Any]] = {}

    def take_snapshot(self, range_env: RangeEnvironment, snapshot_id: Optional[str] = None) -> str:
        """Captures asset state, certificates, and configuration before attack execution."""
        snap_id = snapshot_id or f"snap-{range_env.range_id}-{int(time.time() * 1000)}"
        captured_state = {}
        for asset_id, asset in range_env.assets.items():
            captured_state[asset_id] = {
                "active_services": copy.deepcopy(asset.active_services),
                "state_snapshot": copy.deepcopy(asset.state_snapshot),
                "timestamp": time.time(),
            }
        self._snapshots[snap_id] = {
            "range_id": range_env.range_id,
            "assets": captured_state,
            "created_at": time.time(),
        }
        return snap_id

    def restore_snapshot(self, range_env: RangeEnvironment, snapshot_id: str) -> bool:
        """Restores cyber range assets to their exact baseline snapshot."""
        if snapshot_id not in self._snapshots:
            raise RangeTeardownError(f"Snapshot {snapshot_id} not found.")

        snap = self._snapshots[snapshot_id]
        if snap["range_id"] != range_env.range_id:
            raise RangeTeardownError(f"Snapshot {snapshot_id} belongs to {snap['range_id']}, not {range_env.range_id}")

        for asset_id, state in snap["assets"].items():
            if asset_id in range_env.assets:
                range_env.assets[asset_id].active_services = copy.deepcopy(state["active_services"])
                range_env.assets[asset_id].state_snapshot = copy.deepcopy(state["state_snapshot"])

        range_env.active_scenario_id = None
        range_env.active_campaign_id = None
        range_env.status = RangeStatus.IDLE
        return True

    def teardown_range(self, range_env: RangeEnvironment) -> None:
        """Cleans up active sessions and resets range status."""
        range_env.status = RangeStatus.TEARDOWN
        range_env.active_scenario_id = None
        range_env.active_campaign_id = None
        range_env.status = RangeStatus.IDLE
