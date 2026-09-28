"""
Session Revocation Controller.
Terminates compromised sessions, blacklists tokens, and triggers audit records.
"""
from typing import Dict, List, Optional, Any
import time

from .monitor import ActiveSession, SessionStatus, SessionMonitor


class SessionRevocationManager:
    """Handles immediate mid-session revocation and auditing."""

    def __init__(self, monitor: SessionMonitor):
        self.monitor = monitor
        self._revocations: List[Dict[str, Any]] = []

    def revoke_session(self, session_id: str, actor: str, reason: str) -> ActiveSession:
        session = self.monitor.get_session(session_id)
        if not session:
            raise KeyError(f"Session {session_id} not found.")

        session.status = SessionStatus.REVOKED
        session.last_evaluated_at = time.time()

        revocation_entry = {
            "session_id": session_id,
            "identity_id": session.identity_id,
            "device_id": session.device_id,
            "actor": actor,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._revocations.append(revocation_entry)
        return session

    def list_revocations(self) -> List[Dict[str, Any]]:
        return list(self._revocations)
