"""
Phase 24 — Post-Incident Monitoring & Watchers (Component 25)
Schedules post-remediation monitoring windows (1h, 24h, 7d, 30d, 90d) to detect regression or drift.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class WatcherStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    TRIGGERED_RECURRENCE = "TRIGGERED_RECURRENCE"
    CANCELLED = "CANCELLED"


@dataclass
class WatcherWindow:
    window_label: str  # 1h, 24h, 7d, 30d, 90d
    duration_seconds: float
    check_interval_seconds: float
    last_checked_at: float = 0.0
    completed: bool = False


@dataclass
class ResponseWatcherEntry:
    watcher_id: str
    incident_id: str
    asset_id: str
    monitored_detection: str
    status: WatcherStatus = WatcherStatus.ACTIVE
    created_at: float = field(default_factory=time.time)
    windows: List[WatcherWindow] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    recurrence_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseWatcher:
    """Tracks remediated assets across escalating time windows to ensure sustained operational health."""

    def __init__(self):
        self.active_watchers: Dict[str, ResponseWatcherEntry] = {}

    def register_watcher(self, incident_id: str, asset_id: str, detection_rule: str) -> ResponseWatcherEntry:
        wid = f"WATCH-{uuid.uuid4().hex[:6].upper()}"
        entry = ResponseWatcherEntry(
            watcher_id=wid,
            incident_id=incident_id,
            asset_id=asset_id,
            monitored_detection=detection_rule,
            windows=[
                WatcherWindow("1h", 3600, 300),
                WatcherWindow("24h", 86400, 3600),
                WatcherWindow("7d", 604800, 14400),
                WatcherWindow("30d", 2592000, 86400),
            ]
        )
        self.active_watchers[wid] = entry
        return entry

    def record_check(self, watcher_id: str, recurrence_found: bool, details: str = "") -> ResponseWatcherEntry:
        w = self.active_watchers.get(watcher_id)
        if not w:
            raise KeyError(f"Watcher {watcher_id} not found")

        w.observations.append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Check result: Recurrence={recurrence_found}. {details}")
        if recurrence_found:
            w.status = WatcherStatus.TRIGGERED_RECURRENCE
            w.recurrence_detected = True
        return w
