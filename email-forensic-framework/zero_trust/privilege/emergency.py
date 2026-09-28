"""
Emergency Break-Glass Access Controller.
Component 46: High-audit emergency access for severe outages and critical incident response.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class BreakGlassStatus(str, Enum):
    INITIATED = "INITIATED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    POST_INCIDENT_REVIEWED = "POST_INCIDENT_REVIEWED"


@dataclass
class BreakGlassSession:
    session_id: str
    requester_id: str
    incident_reference: str  # e.g., CASE-991, OUTAGE-102
    target_service: str
    justification: str
    approver_id: str
    duration_minutes: int = 15
    status: BreakGlassStatus = BreakGlassStatus.ACTIVE
    activated_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 900)  # 15 mins default
    actions_performed: List[str] = field(default_factory=list)
    review_notes: Optional[str] = None

    def is_active(self) -> bool:
        if self.status != BreakGlassStatus.ACTIVE:
            return False
        return time.time() <= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "requester_id": self.requester_id,
            "incident_reference": self.incident_reference,
            "target_service": self.target_service,
            "justification": self.justification,
            "approver_id": self.approver_id,
            "duration_minutes": self.duration_minutes,
            "status": self.status.value if isinstance(self.status, BreakGlassStatus) else self.status,
            "expires_at": self.expires_at,
            "is_active": self.is_active(),
            "actions_performed_count": len(self.actions_performed),
        }


class EmergencyAccessController:
    """Manages break-glass emergency sessions and mandatory post-incident audit reviews."""

    def __init__(self):
        self._sessions: Dict[str, BreakGlassSession] = {}

    def activate_break_glass(
        self,
        requester_id: str,
        approver_id: str,
        incident_ref: str,
        target_service: str,
        justification: str,
        duration_minutes: int = 15,
    ) -> BreakGlassSession:
        if requester_id == approver_id:
            raise PermissionError("Separation of Duties: Break-glass requires independent approver authorization.")

        now = time.time()
        sid = f"BG-{uuid.uuid4().hex[:6].upper()}"
        session = BreakGlassSession(
            session_id=sid,
            requester_id=requester_id,
            approver_id=approver_id,
            incident_reference=incident_ref,
            target_service=target_service,
            justification=justification,
            duration_minutes=duration_minutes,
            activated_at=now,
            expires_at=now + (duration_minutes * 60),
        )
        self._sessions[sid] = session
        return session

    def record_action(self, session_id: str, action: str):
        session = self._sessions.get(session_id)
        if session and session.is_active():
            session.actions_performed.append(f"[{time.strftime('%X')}] {action}")

    def complete_post_incident_review(self, session_id: str, reviewer_id: str, notes: str):
        session = self._sessions.get(session_id)
        if not session:
            raise KeyError(f"Break-glass session {session_id} not found.")
        session.status = BreakGlassStatus.POST_INCIDENT_REVIEWED
        session.review_notes = f"Reviewed by {reviewer_id}: {notes}"
        return session

    def list_sessions(self) -> List[BreakGlassSession]:
        return list(self._sessions.values())
