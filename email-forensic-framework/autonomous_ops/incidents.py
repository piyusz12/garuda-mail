"""Garuda Phase 35: Module O - Operational Incident Response & Recovery Lifecycle.
Manages incidents through DETECTED -> CLASSIFIED -> RISK_ASSESSED -> CONTAINMENT -> RECOVERY -> VERIFICATION -> RESOLVED.
Enforces that quarantined security incidents require manual administrative clearance before re-admission.
"""
from typing import Dict, List, Optional, Any
import time
import uuid

from autonomous_ops.models import (
    OperationalIncident,
    IncidentSeverity,
    IncidentLifecycleStatus,
)


class IncidentLifecycleManager:
    """Orchestrates end-to-end operational incident resolution with auditable timeline tracking."""

    def __init__(self):
        self._incidents: Dict[str, OperationalIncident] = {}
        self._seed_sample_incidents()

    def declare_incident(
        self,
        title: str,
        severity: IncidentSeverity,
        target_resource: str,
        detection_source: str,
        description: str,
    ) -> OperationalIncident:
        """Creates and logs a new operational incident at the DETECTED stage."""
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        incident = OperationalIncident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status=IncidentLifecycleStatus.DETECTED,
            target_resource=target_resource,
            detection_source=detection_source,
            description=description,
        )
        incident.add_timeline_event(IncidentLifecycleStatus.DETECTED, f"Incident detected by {detection_source}: {description}")
        self._incidents[incident_id] = incident
        return incident

    def advance_stage(
        self,
        incident_id: str,
        target_stage: IncidentLifecycleStatus,
        detail: str,
        actions_taken: Optional[List[str]] = None,
    ) -> OperationalIncident:
        """Transitions an incident to the next lifecycle stage."""
        incident = self._incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        # Security check: if resource is a quarantined node, cannot be auto-resolved without explicit human clearance
        if "QUARANTINE" in incident.title.upper() and target_stage == IncidentLifecycleStatus.RESOLVED:
            if not any("HUMAN_SECURITY_CLEARANCE" in a for a in (actions_taken or [])):
                raise PermissionError("Quarantined nodes cannot be automatically resolved without human security officer sign-off")

        if actions_taken:
            if target_stage == IncidentLifecycleStatus.CONTAINMENT:
                incident.containment_actions.extend(actions_taken)
            elif target_stage == IncidentLifecycleStatus.RECOVERY:
                incident.recovery_actions.extend(actions_taken)

        incident.add_timeline_event(target_stage, detail)

        if target_stage == IncidentLifecycleStatus.RESOLVED:
            incident.resolved_at = time.time()

        return incident

    def get_incident(self, incident_id: str) -> Optional[OperationalIncident]:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: Optional[IncidentLifecycleStatus] = None) -> List[Dict[str, Any]]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        incidents.sort(key=lambda i: i.detected_at, reverse=True)
        return [i.to_dict() for i in incidents]

    def _seed_sample_incidents(self):
        inc1 = self.declare_incident(
            title="Inference Worker Heartbeat Failure",
            severity=IncidentSeverity.HIGH,
            target_resource="NODE-002",
            detection_source="TelemetryHeartbeatProbe",
            description="Worker NODE-002 stopped responding to periodic ping probes for > 30 seconds",
        )
        self.advance_stage(
            inc1.incident_id,
            IncidentLifecycleStatus.CLASSIFIED,
            "Classified as unrecoverable worker node drop. Active jobs require rerouting.",
        )
        self.advance_stage(
            inc1.incident_id,
            IncidentLifecycleStatus.CONTAINMENT,
            "Removed NODE-002 from scheduler eligibility table. Drained active connections.",
            actions_taken=["DRAIN_WORKER", "ISOLATE_FROM_DISPATCH"],
        )
        self.advance_stage(
            inc1.incident_id,
            IncidentLifecycleStatus.RECOVERY,
            "Rerouted 2 eligible idempotent jobs to NODE-001. Replacement worker verified healthy.",
            actions_taken=["REROUTE_JOBS", "VERIFY_NODE_001"],
        )
        self.advance_stage(
            inc1.incident_id,
            IncidentLifecycleStatus.VERIFICATION,
            "P95 latency normalized to 480ms on replacement node. No job drops observed.",
        )
        self.advance_stage(
            inc1.incident_id,
            IncidentLifecycleStatus.RESOLVED,
            "Incident successfully resolved with zero customer payload loss.",
        )

        inc2 = self.declare_incident(
            title="Suspicious Egress Quarantine",
            severity=IncidentSeverity.CRITICAL,
            target_resource="NODE-004-QUARANTINED",
            detection_source="AirGapPolicyMonitor",
            description="Node attempted egress to external IP outside sovereign air-gapped boundary",
        )
        self.advance_stage(
            inc2.incident_id,
            IncidentLifecycleStatus.CONTAINMENT,
            "Quarantined node network interface and revoked cryptographic JWT delegation keys",
            actions_taken=["NETWORK_ISOLATE", "REVOKE_KEYS"],
        )
