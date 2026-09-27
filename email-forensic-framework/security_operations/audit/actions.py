"""
Phase 25 — Action Audit Ledger
Maintains append-only tamper-evident logs of executed defensive actions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import uuid


@dataclass
class ActionAuditRecord:
    audit_id: str
    action_id: str
    case_id: str
    action_type: str
    target: str
    actor: str
    policy_id: str
    decision_id: str
    snapshot_before: Optional[Dict[str, Any]]
    snapshot_after: Optional[Dict[str, Any]]
    result_status: str
    verification_outcome: str
    timestamp: float = field(default_factory=time.time)


class ActionAuditLedger:
    """Stores append-only audit entries for every action executed in the environment."""

    def __init__(self):
        self._entries: List[ActionAuditRecord] = []

    def record_action(
        self,
        action_id: str,
        case_id: str,
        action_type: str,
        target: str,
        actor: str,
        policy_id: str,
        decision_id: str,
        snapshot_before: Optional[Dict[str, Any]],
        snapshot_after: Optional[Dict[str, Any]],
        result_status: str,
        verification_outcome: str = "PENDING",
    ) -> ActionAuditRecord:
        rec = ActionAuditRecord(
            audit_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
            action_id=action_id,
            case_id=case_id,
            action_type=action_type,
            target=target,
            actor=actor,
            policy_id=policy_id,
            decision_id=decision_id,
            snapshot_before=snapshot_before,
            snapshot_after=snapshot_after,
            result_status=result_status,
            verification_outcome=verification_outcome,
        )
        self._entries.append(rec)
        return rec

    def list_entries(self, case_id: Optional[str] = None) -> List[ActionAuditRecord]:
        if case_id:
            return [e for e in self._entries if e.case_id == case_id]
        return list(self._entries)
