"""
Continuous Access Re-Evaluation Engine.
Component 51 & 52: Listens for contextual changes during active sessions and re-runs trust evaluation.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from .monitor import ActiveSession, SessionStatus, SessionMonitor
from zero_trust.decision.engine import PolicyDecisionPoint
from zero_trust.decision.context import AccessRequestContext


class ReevaluationEvent(str, Enum):
    POSTURE_CHANGED = "POSTURE_CHANGED"
    IDENTITY_RISK_CHANGED = "IDENTITY_RISK_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    SERVICE_RISK_CHANGED = "SERVICE_RISK_CHANGED"
    SESSION_ANOMALY = "SESSION_ANOMALY"
    POLICY_CHANGED = "POLICY_CHANGED"


@dataclass
class ReevaluationResult:
    session_id: str
    event: ReevaluationEvent
    previous_status: str
    new_status: str
    new_decision: str
    action_taken: str  # KEEP, STEP_UP, RESTRICT, REVOKE
    reasons: List[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "event": self.event.value if isinstance(self.event, ReevaluationEvent) else self.event,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "new_decision": self.new_decision,
            "action_taken": self.action_taken,
            "reasons": self.reasons,
            "timestamp": self.timestamp,
        }


class ContinuousAccessEvaluator:
    """Reevaluates active sessions upon context change events."""

    def __init__(self, monitor: SessionMonitor, pdp: PolicyDecisionPoint):
        self.monitor = monitor
        self.pdp = pdp
        self._history: List[ReevaluationResult] = []

    def trigger_reevaluation(
        self,
        session_id: str,
        event: ReevaluationEvent,
        updated_signals: Optional[Dict[str, Any]] = None,
    ) -> ReevaluationResult:
        session = self.monitor.get_session(session_id)
        if not session:
            raise KeyError(f"Active session {session_id} not found.")

        signals = updated_signals or {}
        prev_status = session.status.value

        # Update session with new signals
        if "device_posture_score" in signals:
            session.device_posture_score = signals["device_posture_score"]
        elif signals.get("device_posture") == "NONCOMPLIANT":
            session.device_posture_score = 0.1
        elif signals.get("device_posture") == "DEGRADED":
            session.device_posture_score = 0.5

        if "session_risk_score" in signals:
            session.session_risk_score = signals["session_risk_score"]
        elif signals.get("session_risk") in ("HIGH", "CRITICAL"):
            session.session_risk_score = 75.0
        elif signals.get("session_risk") == "MEDIUM":
            session.session_risk_score = 40.0

        if "ja4" in signals:
            session.ja4 = signals["ja4"]
        if "certificate_id" in signals:
            session.certificate_id = signals["certificate_id"]

        # Build access request context
        posture_str = signals.get("device_posture") or ("HEALTHY" if session.device_posture_score >= 0.8 else ("DEGRADED" if session.device_posture_score >= 0.5 else "NONCOMPLIANT"))
        session_risk_str = signals.get("session_risk") or ("CRITICAL" if session.session_risk_score >= 75 else ("HIGH" if session.session_risk_score >= 50 else ("MEDIUM" if session.session_risk_score >= 30 else "LOW")))
        managed_bool = signals.get("device_managed") if "device_managed" in signals else (session.device_posture_score > 0.4)

        ctx = AccessRequestContext(
            subject_id=session.identity_id,
            subject_group="security-ops",  # Lookup group
            subject_role="ANALYST",
            device_id=session.device_id,
            device_managed=managed_bool,
            device_posture=posture_str,
            resource_id=session.service_id,
            resource_classification=signals.get("resource_classification", "CRITICAL"),
            action="read",
            session_id=session.session_id,
            session_risk=session_risk_str,
            ja4=session.ja4,
            tls_version=session.tls_version,
            client_ip=session.client_ip,
        )

        # Evaluate against PDP without cache
        dec_record = self.pdp.evaluate_access(ctx, use_cache=False)
        new_dec = dec_record.decision

        action_taken = "KEEP"
        if new_dec == "DENY":
            session.status = SessionStatus.REVOKED
            action_taken = "REVOKE"
        elif new_dec == "STEP_UP":
            session.status = SessionStatus.STEP_UP_PENDING
            action_taken = "STEP_UP"
        elif new_dec == "RESTRICT":
            session.status = SessionStatus.RESTRICTED
            action_taken = "RESTRICT"
        else:
            session.status = SessionStatus.ACTIVE
            action_taken = "KEEP"

        session.last_evaluated_at = time.time()

        res = ReevaluationResult(
            session_id=session_id,
            event=event,
            previous_status=prev_status,
            new_status=session.status.value,
            new_decision=new_dec,
            action_taken=action_taken,
            reasons=dec_record.reasons,
        )
        self._history.append(res)
        return res

    def get_history(self, session_id: Optional[str] = None) -> List[ReevaluationResult]:
        if session_id:
            return [h for h in self._history if h.session_id == session_id]
        return list(self._history)
