"""
Phase 25 — SLA Tracking & Escalation Engine
Monitors operational SLAs across priority tiers (Critical 5m, High 15m) and triggers escalations.
"""

from typing import Dict, List, Optional, Any, Tuple
import time
from ..cases.cases import Case, CasePriority, CaseStatus


class SLATracker:
    """Monitors case lifecycle milestones against enterprise operational SLAs."""

    # Priority -> (triage_sla_seconds, response_sla_seconds)
    SLA_LIMITS = {
        CasePriority.CRITICAL: (300, 1800),     # 5 min triage, 30 min response
        CasePriority.HIGH: (900, 7200),         # 15 min triage, 2 hr response
        CasePriority.MEDIUM: (3600, 28800),     # 1 hr triage, 8 hr response
        CasePriority.LOW: (86400, 259200),      # 1 day triage, 3 days response
    }

    @classmethod
    def check_sla(cls, case: Case, current_time: Optional[float] = None) -> Dict[str, Any]:
        now = current_time or time.time()
        elapsed = now - case.created_at
        triage_limit, response_limit = cls.SLA_LIMITS.get(case.priority, (3600, 28800))

        is_triaged = case.status != CaseStatus.NEW
        is_resolved = case.status in (CaseStatus.RESOLVED, CaseStatus.CLOSED)

        triage_breached = not is_triaged and elapsed > triage_limit
        response_breached = not is_resolved and elapsed > response_limit

        case.sla_breached = triage_breached or response_breached

        return {
            "case_id": case.case_id,
            "priority": case.priority.value,
            "elapsed_seconds": round(elapsed, 1),
            "triage_limit_seconds": triage_limit,
            "response_limit_seconds": response_limit,
            "triage_breached": triage_breached,
            "response_breached": response_breached,
            "is_sla_breached": case.sla_breached,
        }


class EscalationEngine:
    """Evaluates case duration and lack of acknowledgement to trigger automated escalations."""

    @classmethod
    def evaluate_escalation(cls, case: Case, current_time: Optional[float] = None) -> Tuple[bool, str]:
        now = current_time or time.time()
        elapsed = now - case.created_at

        # If critical case unacknowledged after 10 minutes -> escalate
        if case.priority == CasePriority.CRITICAL and case.status == CaseStatus.NEW and elapsed > 600:
            case.status = CaseStatus.ESCALATED
            return True, "Critical case unacknowledged for >10m. Escalated to Security Lead."
        elif case.priority == CasePriority.HIGH and case.status == CaseStatus.NEW and elapsed > 1200:
            case.status = CaseStatus.ESCALATED
            return True, "High priority case unacknowledged for >20m. Escalated to Incident Commander."
        return False, "SLA within bounds."
