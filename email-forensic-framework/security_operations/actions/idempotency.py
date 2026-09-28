"""
Phase 25 — Action Idempotency & Concurrency Locks
Guarantees exactly-once execution semantics and prevents conflicting concurrent modifications.
"""

from typing import Dict, Optional, Any, Set, Tuple
import hashlib
import time


class IdempotencyManager:
    """Tracks action idempotency keys to prevent duplicate operations."""

    def __init__(self):
        # idempotency_key -> {"completed_at": float, "result": Any}
        self._executed_actions: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def compute_key(case_id: str, action_type: str, target: str) -> str:
        raw = f"{case_id}:{action_type}:{target}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_executed(self, key: str) -> Tuple[bool, Any]:
        if key in self._executed_actions:
            entry = self._executed_actions[key]
            return True, entry["result"]
        return False, None

    def record_execution(self, key: str, result: Any):
        self._executed_actions[key] = {
            "completed_at": time.time(),
            "result": result,
        }

    def clear(self):
        self._executed_actions.clear()


class ConcurrencyLockManager:
    """Manages granular locks for cases, assets, and active changes."""

    def __init__(self):
        self._locked_assets: Dict[str, str] = {}  # asset_id -> case_id
        self._locked_cases: Set[str] = set()

    def acquire_asset_lock(self, asset_id: str, case_id: str) -> bool:
        current_holder = self._locked_assets.get(asset_id)
        if current_holder and current_holder != case_id:
            return False  # Conflict: another case holds lock
        self._locked_assets[asset_id] = case_id
        return True

    def release_asset_lock(self, asset_id: str, case_id: str):
        if self._locked_assets.get(asset_id) == case_id:
            del self._locked_assets[asset_id]

    def is_asset_locked(self, asset_id: str) -> bool:
        return asset_id in self._locked_assets

    def clear(self):
        self._locked_assets.clear()
        self._locked_cases.clear()  # type alias
