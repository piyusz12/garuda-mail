"""
Identity Copilot & Zero Trust Diagnostic Assistant.
Answers complex governance and operational queries:
- "Why was this session denied?"
- "Who can access this service?"
- "Why can this identity access this resource?"
- "Why can't this identity access?"
"""
from typing import Dict, List, Optional, Any

from zero_trust.decision.engine import PolicyDecisionPoint, AccessDecisionRecord
from zero_trust.sessions.monitor import SessionMonitor
from identity.ingestion.users import UserIdentityRepository
from identity.ingestion.services import ServiceIdentityRepository
from identity.graph.temporal import TemporalIdentityGraph


class IdentityCopilot:
    """Intelligent Copilot for Zero-Trust Access Analysis and Governance."""

    def __init__(
        self,
        pdp: PolicyDecisionPoint,
        session_monitor: SessionMonitor,
        user_repo: UserIdentityRepository,
        service_repo: ServiceIdentityRepository,
        graph: Optional[TemporalIdentityGraph] = None,
    ):
        self.pdp = pdp
        self.session_monitor = session_monitor
        self.user_repo = user_repo
        self.service_repo = service_repo
        self.graph = graph or TemporalIdentityGraph()

    def explain_session_decision(self, session_id: str) -> Dict[str, Any]:
        """Component 60 & 93: Explains why a session was allowed, denied, or stepped-up."""
        session = self.session_monitor.get_session(session_id)
        if not session:
            return {"error": f"Session {session_id} not found"}

        # Find latest audit entry for this session
        audits = [a for a in self.pdp.get_audit_log(500) if a.subject_id == session.identity_id and a.resource_id == session.service_id]
        latest_audit = audits[-1] if audits else None

        reasons = latest_audit.reasons if latest_audit else ["Session evaluated under active zero trust policy."]
        decision = latest_audit.decision if latest_audit else session.status.value

        return {
            "session_id": session.session_id,
            "identity_id": session.identity_id,
            "device_id": session.device_id,
            "service_id": session.service_id,
            "decision": decision,
            "status": session.status.value,
            "reasons": reasons,
            "risk_factors": latest_audit.risk_factors if latest_audit else [],
            "posture_score": session.device_posture_score,
            "session_risk_score": session.session_risk_score,
            "ja4": session.ja4,
            "tls_version": session.tls_version,
            "policy_id": latest_audit.matched_policy_id if latest_audit else "default",
        }

    def who_can_access(self, service_id: str) -> Dict[str, Any]:
        """Component 62: Identifies all identities that can access a specific service."""
        service = self.service_repo.get(service_id)
        if not service:
            return {"error": f"Service {service_id} not found"}

        allowed_identities = []
        for user in self.user_repo.list_all():
            # Check if user matches allowed source groups
            if any(g in service.allowed_source_groups for g in user.groups):
                allowed_identities.append({
                    "identity_id": user.identity_id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "matched_group": [g for g in user.groups if g in service.allowed_source_groups],
                    "title": user.title,
                })

        return {
            "service_id": service_id,
            "service_name": service.service_name,
            "classification": service.classification.value,
            "allowed_identities_count": len(allowed_identities),
            "allowed_identities": allowed_identities,
        }

    def why_can_they_access(self, identity_id: str, service_id: str) -> Dict[str, Any]:
        """Component 63: Traces the permission chain: USER -> GROUP -> ROLE -> POLICY -> SERVICE."""
        user = self.user_repo.get(identity_id)
        service = self.service_repo.get(service_id)

        if not user or not service:
            return {"error": "Identity or service not found"}

        path = self.graph.trace_access_path(identity_id, service_id)

        return {
            "identity_id": identity_id,
            "username": user.username,
            "service_id": service_id,
            "service_name": service.service_name,
            "relationship_path": path,
            "explanation": f"User '{user.full_name}' possesses groups {user.groups} permitting access to {service.service_name}.",
        }

    def why_cant_they_access(self, identity_id: str, service_id: str, device_id: str) -> Dict[str, Any]:
        """Component 64: Shows the exact blocking conditions preventing access."""
        from zero_trust.decision.context import AccessRequestContext
        user = self.user_repo.get(identity_id)
        service = self.service_repo.get(service_id)

        ctx = AccessRequestContext(
            subject_id=identity_id,
            subject_group=user.groups[0] if (user and user.groups) else "general",
            subject_role=user.roles[0] if (user and user.roles) else "USER",
            device_id=device_id,
            device_managed=False,  # Test unmanaged
            device_posture="NONCOMPLIANT",
            resource_id=service_id,
            resource_classification=service.classification.value if service else "INTERNAL",
            action="read",
        )
        dec = self.pdp.evaluate_access(ctx, use_cache=False)

        return {
            "identity_id": identity_id,
            "service_id": service_id,
            "device_id": device_id,
            "decision": dec.decision,
            "blocking_factors": dec.risk_factors or ["No authorization policy matched."],
            "reasons": dec.reasons,
        }
