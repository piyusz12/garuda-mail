"""
Phase 24 — Action Audit Engine (Component 42)
Maintains an immutable, append-only ledger of every requested, authorized, executed, and rolled back action.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import hashlib
import json
import time


@dataclass
class ActionAuditEntry:
    entry_id: str
    action_id: str
    incident_id: str
    action_name: str
    requested_by: str
    approved_by: List[str]
    target_asset: str
    action_hash: str
    started_at: float
    completed_at: float
    status: str
    result_message: str
    prev_entry_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ActionAuditor:
    """Tamper-evident blockchain-style hash-chained action ledger for regulatory compliance."""

    def __init__(self):
        self.ledger: List[ActionAuditEntry] = []
        self._last_hash = "GENESIS_ACTION_HASH_00000000000000000000000000000000000000000000"

    def record_action_execution(
        self,
        action: Any,
        incident_id: str,
        requested_by: str = "agent",
        approved_by: Optional[List[str]] = None
    ) -> ActionAuditEntry:
        res = getattr(action, "result", None)
        started = getattr(res, "started_at", time.time())
        completed = getattr(res, "completed_at", time.time())
        status = getattr(action, "status", None)
        status_val = getattr(status, "value", str(status))
        msg = getattr(res, "output_message", "")

        entry_id = f"AUD-ACT-{len(self.ledger) + 1:05d}"
        action_hash = action.compute_action_hash() if hasattr(action, "compute_action_hash") else "NO_HASH"

        canonical_data = {
            "entry_id": entry_id,
            "action_id": action.action_id,
            "incident_id": incident_id,
            "action_name": action.name,
            "action_hash": action_hash,
            "status": status_val,
            "prev_hash": self._last_hash
        }
        current_hash = hashlib.sha256(json.dumps(canonical_data, sort_keys=True).encode("utf-8")).hexdigest()

        entry = ActionAuditEntry(
            entry_id=entry_id,
            action_id=action.action_id,
            incident_id=incident_id,
            action_name=action.name,
            requested_by=requested_by,
            approved_by=approved_by or [],
            target_asset=action.target_asset,
            action_hash=action_hash,
            started_at=started,
            completed_at=completed,
            status=status_val,
            result_message=msg,
            prev_entry_hash=self._last_hash,
            entry_hash=current_hash
        )

        self._last_hash = current_hash
        self.ledger.append(entry)
        return entry
