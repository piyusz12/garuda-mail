"""
Phase 25 — Investigation & Case State Machine
Defines valid lifecycle state transitions, transition guards, and audit trail hooks.
"""

from typing import Set, Dict, List
from ..cases.cases import CaseStatus, Case


class CaseStateMachine:
    """Validates and applies state transitions for operational cases."""

    VALID_TRANSITIONS: Dict[CaseStatus, Set[CaseStatus]] = {
        CaseStatus.NEW: {
            CaseStatus.TRIAGED,
            CaseStatus.INVESTIGATING,
            CaseStatus.DUPLICATE,
            CaseStatus.FALSE_POSITIVE,
        },
        CaseStatus.TRIAGED: {
            CaseStatus.INVESTIGATING,
            CaseStatus.BENIGN,
            CaseStatus.FALSE_POSITIVE,
            CaseStatus.ESCALATED,
        },
        CaseStatus.INVESTIGATING: {
            CaseStatus.EVIDENCE_COLLECTED,
            CaseStatus.SUSPENDED,
            CaseStatus.FALSE_POSITIVE,
        },
        CaseStatus.EVIDENCE_COLLECTED: {
            CaseStatus.ASSESSED,
            CaseStatus.INVESTIGATING,
        },
        CaseStatus.ASSESSED: {
            CaseStatus.AWAITING_DECISION,
            CaseStatus.ESCALATED,
        },
        CaseStatus.AWAITING_DECISION: {
            CaseStatus.RESPONDING,
            CaseStatus.RESOLVED,
            CaseStatus.ESCALATED,
        },
        CaseStatus.RESPONDING: {
            CaseStatus.VERIFYING,
            CaseStatus.ESCALATED,
        },
        CaseStatus.VERIFYING: {
            CaseStatus.RESOLVED,
            CaseStatus.RESPONDING,
            CaseStatus.ESCALATED,
        },
        CaseStatus.RESOLVED: {
            CaseStatus.CLOSED,
            CaseStatus.REOPENED,
        },
        CaseStatus.CLOSED: {
            CaseStatus.REOPENED,
        },
        CaseStatus.REOPENED: {
            CaseStatus.INVESTIGATING,
            CaseStatus.RESPONDING,
        },
        CaseStatus.ESCALATED: {
            CaseStatus.AWAITING_DECISION,
            CaseStatus.RESPONDING,
            CaseStatus.RESOLVED,
        },
        CaseStatus.FALSE_POSITIVE: set(),
        CaseStatus.BENIGN: set(),
        CaseStatus.DUPLICATE: set(),
        CaseStatus.SUSPENDED: {CaseStatus.INVESTIGATING},
    }

    @classmethod
    def can_transition(cls, current: CaseStatus, target: CaseStatus) -> bool:
        if current == target:
            return True
        return target in cls.VALID_TRANSITIONS.get(current, set())

    @classmethod
    def transition(cls, case: Case, target: CaseStatus, actor: str = "orchestrator", reason: str = ""):
        if not cls.can_transition(case.status, target):
            raise ValueError(
                f"Illegal state transition from '{case.status.value}' to '{target.value}' for case '{case.case_id}'."
            )
        case.transition_to(target, actor=actor, reason=reason)
