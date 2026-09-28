"""
API Security Anomaly Detection Engine.
Component 32: Detects abnormal API access patterns, token replay, authorization bypass, and caller drift.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid
import time

from api_security.inventory import APIRegistry, AuthType, DataClassification
from api_security.behavior import APIAccessEvent, APIBaseline


class APIAnomalySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class APIAnomalyFinding:
    finding_id: str
    endpoint_id: str
    severity: APIAnomalySeverity
    category: str
    title: str
    description: str
    evidence: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "endpoint_id": self.endpoint_id,
            "severity": self.severity.value if isinstance(self.severity, APIAnomalySeverity) else self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


class APISecurityDetector:
    """Evaluates API traffic against API definitions and behavioral baselines."""

    def __init__(self, registry: Optional[APIRegistry] = None):
        self.registry = registry or APIRegistry()
        self._baselines: Dict[str, APIBaseline] = {}
        self._seed_default_baselines()

    def _seed_default_baselines(self) -> None:
        # API-CERT-01 baseline
        self.register_baseline(
            APIBaseline(
                endpoint_id="API-CERT-01",
                approved_callers={"USER-1192", "SERVICE-91", "SEC-ADMIN-01"},
                approved_workloads={"WORKLOAD-991", "WORKLOAD-101"},
                allowed_methods={"POST"},
                max_normal_rpm=600,
            )
        )
        # API-FORENSIC-01 baseline
        self.register_baseline(
            APIBaseline(
                endpoint_id="API-FORENSIC-01",
                approved_callers={"FORENSIC-ANALYST", "SOC-RESPONDER-03"},
                approved_workloads={"WORKLOAD-101"},
                allowed_methods={"GET"},
                max_normal_rpm=300,
            )
        )

    def register_baseline(self, baseline: APIBaseline) -> None:
        self._baselines[baseline.endpoint_id] = baseline

    def inspect_access_event(self, event: APIAccessEvent) -> List[APIAnomalyFinding]:
        """Detect anomalies such as missing auth, mTLS bypass on confidential APIs, and baseline drift."""
        findings: List[APIAnomalyFinding] = []
        endpoint = self.registry.get_endpoint(event.endpoint_id)

        # 1. Missing Authentication Check
        if endpoint and endpoint.auth_type != AuthType.NONE:
            if not event.auth_header_present:
                findings.append(
                    APIAnomalyFinding(
                        finding_id=f"APIFIND-{uuid.uuid4().hex[:8].upper()}",
                        endpoint_id=event.endpoint_id,
                        severity=APIAnomalySeverity.CRITICAL,
                        category="UNAUTHENTICATED_ACCESS_ATTEMPT",
                        title=f"Unauthenticated request to protected endpoint {endpoint.path}",
                        description=f"Request from {event.client_ip} lacked mandatory authentication headers.",
                        evidence=event.to_dict(),
                    )
                )

            # 2. Missing or failed mTLS on mutual-TLS mandated API
            if endpoint.auth_type == AuthType.MTLS and not event.mtls_verified:
                findings.append(
                    APIAnomalyFinding(
                        finding_id=f"APIFIND-{uuid.uuid4().hex[:8].upper()}",
                        endpoint_id=event.endpoint_id,
                        severity=APIAnomalySeverity.CRITICAL,
                        category="MTLS_VERIFICATION_FAILURE",
                        title=f"mTLS handshake verification failed for {endpoint.path}",
                        description=f"Endpoint mandates mutual TLS authentication, but client certificate was absent or invalid.",
                        evidence=event.to_dict(),
                    )
                )

        # 3. Baseline Deviations
        baseline = self._baselines.get(event.endpoint_id)
        if baseline:
            deviations = baseline.check_deviation(event)
            for dev in deviations:
                findings.append(
                    APIAnomalyFinding(
                        finding_id=f"APIFIND-{uuid.uuid4().hex[:8].upper()}",
                        endpoint_id=event.endpoint_id,
                        severity=APIAnomalySeverity.HIGH,
                        category="BEHAVIORAL_ANOMALY",
                        title=f"API access deviation on {event.endpoint_id}",
                        description=f"Detected abnormal API caller pattern: {dev}",
                        evidence={"deviation": dev, "event": event.to_dict()},
                    )
                )

        return findings
