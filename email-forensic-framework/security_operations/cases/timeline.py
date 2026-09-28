"""
Phase 25 — Case Incident Timeline & Evidence Chain
Maintains an immutable, cryptographically hash-chained incident timeline.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import hashlib
import json
import time
import uuid


class CaseTimeline:
    """Manages an immutable, cryptographically hash-chained timeline for a case."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.events: List[Dict[str, Any]] = []
        self._last_hash: str = "GENESIS-" + case_id

    def add_event(
        self,
        stage: str,
        description: str,
        actor: str = "system",
        system: str = "SOAR",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Appends a new event and updates the cryptographic hash chain."""
        ts = timestamp or time.time()
        iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"

        record_to_hash = {
            "event_id": event_id,
            "case_id": self.case_id,
            "previous_hash": self._last_hash,
            "timestamp": ts,
            "stage": stage,
            "description": description,
            "actor": actor,
            "system": system,
            "reason": reason,
            "details": details or {},
        }

        block_bytes = json.dumps(record_to_hash, sort_keys=True, default=str).encode("utf-8")
        current_hash = hashlib.sha256(block_bytes).hexdigest()
        record_to_hash["hash"] = current_hash
        record_to_hash["iso_time"] = iso

        self._last_hash = current_hash
        self.events.append(record_to_hash)
        return record_to_hash

    def get_events(self) -> List[Dict[str, Any]]:
        return list(self.events)

    def verify_integrity(self) -> bool:
        """Verifies the entire hash chain from genesis to head."""
        expected_prev = "GENESIS-" + self.case_id
        for ev in self.events:
            rec = {
                "event_id": ev["event_id"],
                "case_id": self.case_id,
                "previous_hash": expected_prev,
                "timestamp": ev["timestamp"],
                "stage": ev["stage"],
                "description": ev["description"],
                "actor": ev["actor"],
                "system": ev["system"],
                "reason": ev["reason"],
                "details": ev.get("details", {}),
            }
            computed = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode("utf-8")).hexdigest()
            if computed != ev["hash"]:
                return False
            expected_prev = ev["hash"]
        return True
