"""
Service-to-Service API Gateway Enforcement Adapter.
Component 30 & 31: Micro-segmentation and East-West Service-to-Service Authorization.
"""
from typing import Dict, List, Optional, Any
from zero_trust.decision.context import AccessRequestContext
from zero_trust.decision.engine import PolicyDecisionPoint
from .proxy import PolicyEnforcementPoint, EnforcementResult


class ServiceToServiceGateway:
    """Enforces zero-trust authorization on east-west API and microservice calls."""

    def __init__(self, pdp: PolicyDecisionPoint):
        self.pep = PolicyEnforcementPoint(pdp)

    def authorize_call(
        self,
        source_service_id: str,
        target_service_id: str,
        action: str = "read",
        client_cert_valid: bool = True,
        pqc_compliant: bool = True,
    ) -> EnforcementResult:
        ctx = AccessRequestContext(
            subject_id=source_service_id,
            subject_group="service-accounts",
            subject_role="MICROSERVICE",
            device_id=source_service_id,
            device_managed=True,
            device_posture="HEALTHY" if client_cert_valid else "NONCOMPLIANT",
            resource_id=target_service_id,
            resource_classification="CRITICAL",
            action=action,
            tls_version="TLS 1.3",
            session_risk="LOW" if (client_cert_valid and pqc_compliant) else "HIGH",
        )
        return self.pep.enforce(ctx)
