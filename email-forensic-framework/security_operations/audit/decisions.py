"""
Phase 25 — Decision Audit Trail
Maintains an immutable append-only ledger of all automated and human security decisions.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import time
import uuid


@dataclass
class DecisionAuditRecord:
    decision_id: str
    case_id: str
    decision: str
    risk_score: float
    reasons: List[str]
    evidence_pointers: List[str]
    policy_version: str
    actor: str
    timestamp: float = field(default_factory=time.time)


class DecisionAuditLedger:
    """Append-only audit ledger for operational decisions."""

    def __init__(self):
        self._records: List[DecisionAuditRecord] = []

    def record_decision(
        self,
        case_id: str,
        decision: str,
        risk_score: float,
        reasons: List[str],
        evidence_pointers: List[str],
        policy_version: str = "2.5",
        actor: str = "security_automation",
    ) -> DecisionAuditRecord:
        rec = DecisionAuditRecord(
            decision_id=f"DEC-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            decision=decision,
            risk_score=risk_score,
            reasons=reasons,
            evidence_pointers=evidence_pointers,
            policy_version=policy_version,
            actor=actor,
        )
        self._records.append(rec)
        return rec

    def list_records(self, case_id: Optional[str] = None) -> List[DecisionAuditRecord]:
        if case_id:
            return [r for r in self._records if r.case_id == case_id]
        return list(self._records)
