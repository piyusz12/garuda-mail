"""
Phase 25 — Alert Deduplication Engine
Builds fingerprints across asset, time window, event type, rule, JA4, certificate,
and destination to deduplicate alert floods into unified clusters.
"""

from typing import Dict, Optional, Tuple, Any
import hashlib
import time
from .ingest import Alert


class AlertDeduplicator:
    """Detects and deduplicates redundant alerts arriving in a rolling time window."""

    def __init__(self, time_window_seconds: int = 300):
        self.time_window = time_window_seconds
        # fingerprint -> {"alert": Alert, "count": int, "first_seen": float, "last_seen": float}
        self._fingerprints: Dict[str, Dict[str, Any]] = {}

    def compute_fingerprint(self, alert: Alert) -> str:
        """Calculates a deterministic SHA-256 fingerprint for the alert."""
        # Align timestamp to time window bucket
        window_bucket = int(alert.timestamp // self.time_window)
        key_raw = (
            f"{alert.tenant_id}|"
            f"{alert.asset_id}|"
            f"{alert.event_type}|"
            f"{alert.rule_id or ''}|"
            f"{alert.ja4 or ''}|"
            f"{alert.certificate_id or ''}|"
            f"{alert.destination or ''}|"
            f"{window_bucket}"
        )
        return hashlib.sha256(key_raw.encode("utf-8")).hexdigest()

    def process(self, alert: Alert) -> Tuple[bool, Alert, int]:
        """
        Processes an alert through deduplication.
        Returns:
            (is_duplicate, representative_alert, current_hit_count)
        """
        fp = self.compute_fingerprint(alert)
        now = alert.timestamp or time.time()

        if fp in self._fingerprints:
            entry = self._fingerprints[fp]
            entry["count"] += 1
            entry["last_seen"] = now
            # Merge details if new information arrived
            entry["alert"].details.update(alert.details)
            return True, entry["alert"], entry["count"]

        # First occurrence in this window
        self._fingerprints[fp] = {
            "alert": alert,
            "count": 1,
            "first_seen": now,
            "last_seen": now,
        }
        return False, alert, 1

    def get_hit_count(self, alert: Alert) -> int:
        fp = self.compute_fingerprint(alert)
        return self._fingerprints.get(fp, {}).get("count", 1)

    def clear(self):
        self._fingerprints.clear()
