"""
Phase 24 — Approval Audit Log (Components 8, 53)
Retains compliance evidence detailing who approved, when, and cryptographic action verification.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any
import time


@dataclass
class ApprovalAuditEntry:
    entry_id: str
    request_id: str
    incident_id: str
    action_id: str
    approver_id: str
    approver_role: str
    decision: str
    reason: str
    action_hash: str
    timestamp: float
    iso_time: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApprovalAuditor:
    """Retains compliance records for security audits and forensic accountability."""

    def __init__(self):
        self.approval_entries: List[ApprovalAuditEntry] = []

    def record_signature(self, request_id: str, incident_id: str, action_id: str, sig_record: Any) -> ApprovalAuditEntry:
        entry = ApprovalAuditEntry(
            entry_id=f"AUD-APPR-{len(self.approval_entries) + 1:05d}",
            request_id=request_id,
            incident_id=incident_id,
            action_id=action_id,
            approver_id=sig_record.approver_id,
            approver_role=sig_record.approver_role,
            decision=sig_record.decision.value,
            reason=sig_record.reason,
            action_hash=sig_record.action_hash_at_approval,
            timestamp=sig_record.timestamp,
            iso_time=time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(sig_record.timestamp))
        )
        self.approval_entries.append(entry)
        return entry
