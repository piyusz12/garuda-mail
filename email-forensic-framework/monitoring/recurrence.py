"""
Phase 24 — Recurrence Detector (Component 25, 26)
Continuously compares incoming telemetry against remediated incident assets and detections.
"""

from typing import Dict, List, Any, Optional
from monitoring.watchers import ResponseWatcher, ResponseWatcherEntry, WatcherStatus


class RecurrenceDetector:
    """Detects return of previously remediated vulnerabilities."""

    def __init__(self, watcher: ResponseWatcher):
        self.watcher = watcher

    def evaluate_telemetry_batch(self, telemetry_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        recurrences = []
        for w in self.watcher.active_watchers.values():
            if w.status != WatcherStatus.ACTIVE:
                continue

            for evt in telemetry_events:
                evt_asset = evt.get("asset", evt.get("serverIp", ""))
                evt_rule = evt.get("rule_id", evt.get("detection", ""))
                evt_tls = evt.get("tls_version", "")

                is_match = (
                    evt_asset == w.asset_id and
                    (evt_rule == w.monitored_detection or evt_tls in ["TLS 1.0", "TLS 1.1"])
                )

                if is_match:
                    self.watcher.record_check(w.watcher_id, recurrence_found=True, details=f"Observed {evt_tls} on {evt_asset}")
                    recurrences.append({
                        "watcher_id": w.watcher_id,
                        "incident_id": w.incident_id,
                        "asset_id": w.asset_id,
                        "event": evt
                    })
                    break

        return recurrences
