"""
Kubernetes Cluster Runtime Telemetry & Anomaly Monitoring.
Component 26: Observes pod lifecycle, execs, secret access, and privilege mutations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class K8sRuntimeEventType(str, Enum):
    POD_EXEC = "POD_EXEC"
    SECRET_ACCESS = "SECRET_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CONFIGMAP_MUTATION = "CONFIGMAP_MUTATION"
    TOKEN_EXPORT = "TOKEN_EXPORT"
    ANOMALOUS_POD_START = "ANOMALOUS_POD_START"


@dataclass
class K8sRuntimeEvent:
    event_id: str
    event_type: K8sRuntimeEventType
    cluster_id: str
    namespace: str
    pod_name: str
    service_account: str
    actor: str  # User or ServiceAccount invoking the action
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "MEDIUM"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value if isinstance(self.event_type, K8sRuntimeEventType) else self.event_type,
            "cluster_id": self.cluster_id,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "service_account": self.service_account,
            "actor": self.actor,
            "details": self.details,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


class K8sRuntimeMonitor:
    """Monitors live Kubernetes cluster activity and flags suspicious operations."""

    def __init__(self):
        self._events: List[K8sRuntimeEvent] = []

    def record_event(self, event: K8sRuntimeEvent) -> None:
        self._events.append(event)

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        findings = []
        for e in self._events:
            if e.event_type == K8sRuntimeEventType.POD_EXEC and e.namespace == "production":
                findings.append({
                    "finding_id": f"FIND-{e.event_id}",
                    "severity": "CRITICAL",
                    "type": "INTERACTIVE_EXEC_IN_PRODUCTION",
                    "description": f"Actor '{e.actor}' executed interactive shell in production pod '{e.pod_name}'.",
                    "event": e.to_dict(),
                })
            elif e.event_type == K8sRuntimeEventType.TOKEN_EXPORT:
                findings.append({
                    "finding_id": f"FIND-{e.event_id}",
                    "severity": "HIGH",
                    "type": "SERVICE_ACCOUNT_TOKEN_THEFT_RISK",
                    "description": f"Service account token for '{e.service_account}' was accessed or exported.",
                    "event": e.to_dict(),
                })
        return findings

    def get_events(self, limit: int = 50) -> List[K8sRuntimeEvent]:
        return self._events[-limit:]
