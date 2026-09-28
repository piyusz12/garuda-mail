"""
Active Zero-Trust Session Monitor.
Maintains live state of authenticated communication sessions binding users, devices, services, certificates, and JA4s.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESTRICTED = "RESTRICTED"
    STEP_UP_PENDING = "STEP_UP_PENDING"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass
class ActiveSession:
    session_id: str
    identity_id: str
    device_id: str
    service_id: str
    status: SessionStatus = SessionStatus.ACTIVE
    tls_version: str = "TLS 1.3"
    ja4: Optional[str] = None
    certificate_id: Optional[str] = None
    client_ip: str = "10.200.1.44"
    device_posture_score: float = 1.0
    session_risk_score: float = 10.0
    created_at: float = field(default_factory=time.time)
    last_evaluated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "identity_id": self.identity_id,
            "device_id": self.device_id,
            "service_id": self.service_id,
            "status": self.status.value if isinstance(self.status, SessionStatus) else self.status,
            "tls_version": self.tls_version,
            "ja4": self.ja4,
            "certificate_id": self.certificate_id,
            "client_ip": self.client_ip,
            "device_posture_score": round(self.device_posture_score, 2),
            "session_risk_score": round(self.session_risk_score, 1),
            "created_at": self.created_at,
            "last_evaluated_at": self.last_evaluated_at,
        }


class SessionMonitor:
    """Registry and state tracker for active sessions."""

    def __init__(self):
        self._sessions: Dict[str, ActiveSession] = {}

    def register_session(self, session: ActiveSession) -> None:
        self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Optional[ActiveSession]:
        return self._sessions.get(session_id)

    def list_active_sessions(self) -> List[ActiveSession]:
        return [s for s in self._sessions.values() if s.status == SessionStatus.ACTIVE]

    def list_all_sessions(self) -> List[ActiveSession]:
        return list(self._sessions.values())
