"""
Phase 25 — Recovery Tracking & Automated Reopen Logic
Tracks stability monitoring windows (30m, 24h) and reopens closed cases if threats recur.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import time
from ..cases.cases import Case, CaseStatus


@dataclass
class MonitoringSession:
    session_id: str
    case_id: str
    asset_id: str
    started_at: float
    window_duration_seconds: float
    status: str = "ACTIVE"  # ACTIVE, PASSED, RECURRENCE_DETECTED
    last_checked_at: float = field(default_factory=time.time)


class RecoveryTracker:
    """Manages post-remediation stability monitoring windows."""

    def __init__(self):
        self._sessions: Dict[str, MonitoringSession] = {}

    def start_monitoring(
        self,
        case: Case,
        window_duration_seconds: float = 1800,  # 30 min default
    ) -> MonitoringSession:
        sid = f"MON-{case.case_id}"
        sess = MonitoringSession(
            session_id=sid,
            case_id=case.case_id,
            asset_id=case.asset_id,
            started_at=time.time(),
            window_duration_seconds=window_duration_seconds,
        )
        self._sessions[sid] = sess
        return sess

    def check_stability(
        self,
        session_id: str,
        current_time: Optional[float] = None,
        observed_recurrence: bool = False,
    ) -> Dict[str, Any]:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Monitoring session '{session_id}' not found.")

        now = current_time or time.time()
        sess.last_checked_at = now

        if observed_recurrence:
            sess.status = "RECURRENCE_DETECTED"
            return {
                "session_id": session_id,
                "status": "RECURRENCE_DETECTED",
                "message": "Threat recurred during stability window.",
            }

        elapsed = now - sess.started_at
        if elapsed >= sess.window_duration_seconds:
            sess.status = "PASSED"
            return {
                "session_id": session_id,
                "status": "PASSED",
                "message": "Monitoring window elapsed with zero recurrence. Ready for closure.",
            }

        return {
            "session_id": session_id,
            "status": "ACTIVE",
            "elapsed_seconds": round(elapsed, 1),
            "remaining_seconds": round(sess.window_duration_seconds - elapsed, 1),
        }


class ReopenLogic:
    """Detects recurring events and reopens resolved/closed cases with historical linkages."""

    @staticmethod
    def evaluate_recurrence(
        case: Case,
        new_event_type: str,
        asset_id: str,
    ) -> Tuple[bool, str]:
        if case.asset_id == asset_id and case.status in (CaseStatus.RESOLVED, CaseStatus.CLOSED):
            # Recurrence triggered
            case.status = CaseStatus.REOPENED
            case.reopened_from = case.case_id
            case.updated_at = time.time()
            return True, f"Threat condition '{new_event_type}' recurred on asset '{asset_id}'. Case reopened."
        return False, "No recurrence match."
