"""
Phase 24 — Incident Lifecycle State Machine
Governs all status transitions, enforcing prerequisite checks before resolution and closure.
"""

from typing import Dict, List, Optional, Set
import time
from incident.models import Incident, IncidentStatus


class LifecycleTransitionError(Exception):
    pass


class IncidentLifecycleManager:
    """Enforces strict state transitions and closure prerequisites across the 16 incident lifecycle states."""

    ALLOWED_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
        IncidentStatus.NEW: {
            IncidentStatus.TRIAGED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.ACCEPTED_RISK,
        },
        IncidentStatus.TRIAGED: {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINMENT,
            IncidentStatus.REMEDIATION,
            IncidentStatus.WAITING_APPROVAL,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.ACCEPTED_RISK,
        },
        IncidentStatus.INVESTIGATING: {
            IncidentStatus.CONTAINMENT,
            IncidentStatus.REMEDIATION,
            IncidentStatus.WAITING_APPROVAL,
            IncidentStatus.WAITING_EXTERNAL,
            IncidentStatus.FALSE_POSITIVE,
        },
        IncidentStatus.WAITING_APPROVAL: {
            IncidentStatus.CONTAINMENT,
            IncidentStatus.REMEDIATION,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ACCEPTED_RISK,
        },
        IncidentStatus.CONTAINMENT: {
            IncidentStatus.REMEDIATION,
            IncidentStatus.VERIFICATION,
            IncidentStatus.WAITING_APPROVAL,
            IncidentStatus.ROLLBACK,
        },
        IncidentStatus.REMEDIATION: {
            IncidentStatus.VERIFICATION,
            IncidentStatus.ROLLBACK,
            IncidentStatus.WAITING_EXTERNAL,
        },
        IncidentStatus.ROLLBACK: {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.REMEDIATION,
            IncidentStatus.WAITING_APPROVAL,
            IncidentStatus.RECOVERY,
        },
        IncidentStatus.VERIFICATION: {
            IncidentStatus.RECOVERY,
            IncidentStatus.ROLLBACK,
            IncidentStatus.REMEDIATION,
        },
        IncidentStatus.RECOVERY: {
            IncidentStatus.MONITORING,
            IncidentStatus.VERIFICATION,
            IncidentStatus.ROLLBACK,
        },
        IncidentStatus.MONITORING: {
            IncidentStatus.RESOLVED,
            IncidentStatus.REOPENED,
            IncidentStatus.REMEDIATION,
        },
        IncidentStatus.RESOLVED: {
            IncidentStatus.CLOSED,
            IncidentStatus.REOPENED,
        },
        IncidentStatus.CLOSED: {
            IncidentStatus.REOPENED,
        },
        IncidentStatus.REOPENED: {
            IncidentStatus.TRIAGED,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.REMEDIATION,
        },
        IncidentStatus.WAITING_EXTERNAL: {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINMENT,
            IncidentStatus.REMEDIATION,
        },
        IncidentStatus.FALSE_POSITIVE: {
            IncidentStatus.CLOSED,
            IncidentStatus.REOPENED,
        },
        IncidentStatus.ACCEPTED_RISK: {
            IncidentStatus.CLOSED,
            IncidentStatus.REOPENED,
        },
    }

    @classmethod
    def transition(cls, incident: Incident, target_status: IncidentStatus, actor: str = "system", reason: str = "", bypass_prereqs: bool = False) -> Incident:
        """Transitions incident to target status if valid, validating closure/resolution prerequisites."""
        current = incident.status
        allowed = cls.ALLOWED_TRANSITIONS.get(current, set())

        if target_status not in allowed and not bypass_prereqs:
            raise LifecycleTransitionError(
                f"Invalid lifecycle transition from {current.value} to {target_status.value}. "
                f"Allowed destinations: {[s.value for s in allowed]}"
            )

        # Check Component 51 Closure Rules
        if target_status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] and not bypass_prereqs:
            cls._verify_closure_prerequisites(incident, target_status)

        old_status = incident.status
        incident.status = target_status
        incident.updated_at = time.time()
        incident.add_timeline_event(
            event_type="STATUS_CHANGED",
            description=f"Status transitioned from {old_status.value} to {target_status.value}. Reason: {reason or 'Workflow progression'}",
            actor=actor,
            details={"previous_status": old_status.value, "new_status": target_status.value, "reason": reason}
        )
        return incident

    @classmethod
    def _verify_closure_prerequisites(cls, incident: Incident, target_status: IncidentStatus):
        """Component 51: Incident Closure Rules enforcement."""
        # 1. Evidence must be preserved
        if not incident.evidence:
            raise LifecycleTransitionError("Closure rejected: Forensic evidence has not been preserved.")

        # 2. Cannot close if in an unverified state
        timeline_types = [e.event_type for e in incident.timeline]
        if "REMEDIATION_VERIFIED" not in timeline_types and incident.status not in [IncidentStatus.FALSE_POSITIVE, IncidentStatus.ACCEPTED_RISK]:
            raise LifecycleTransitionError("Closure rejected: Remediation has not been verified against telemetry.")
