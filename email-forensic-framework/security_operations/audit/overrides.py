"""
Phase 25 — Analyst Override Ledger
Tracks human interventions, reverses, and overrides of automated operations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import uuid


@dataclass
class AnalystOverrideRecord:
    override_id: str
    action_id: str
    case_id: str
    analyst_id: str
    override_reason: str
    previous_state: str
    new_state: str
    policy_id: str
    timestamp: float = field(default_factory=time.time)


class AnalystOverrideLedger:
    """Maintains an audit trail of human analyst overrides of automated workflows."""

    def __init__(self):
        self._overrides: List[AnalystOverrideRecord] = []

    def record_override(
        self,
        action_id: str,
        case_id: str,
        analyst_id: str,
        override_reason: str,
        previous_state: str,
        new_state: str = "CANCELLED",
        policy_id: str = "POL-DEFAULT",
    ) -> AnalystOverrideRecord:
        rec = AnalystOverrideRecord(
            override_id=f"OVR-{uuid.uuid4().hex[:8].upper()}",
            action_id=action_id,
            case_id=case_id,
            analyst_id=analyst_id,
            override_reason=override_reason,
            previous_state=previous_state,
            new_state=new_state,
            policy_id=policy_id,
        )
        self._overrides.append(rec)
        return rec

    def list_overrides(self, case_id: Optional[str] = None) -> List[AnalystOverrideRecord]:
        if case_id:
            return [o for o in self._overrides if o.case_id == case_id]
        return list(self._overrides)
