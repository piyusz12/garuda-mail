"""
Phase 24 — Incident Manager
Manages the end-to-end incident catalog, converts Phase 23 findings/cases into qualified incidents,
and orchestrates triage, prioritization, and automated reopening.
"""

from typing import Dict, List, Optional, Any
import time
import uuid

from incident.models import Incident, IncidentStatus, IncidentSeverity, IncidentPriority
from incident.triage import IncidentTriageEngine
from incident.priority import PriorityEngine
from incident.lifecycle import IncidentLifecycleManager


class IncidentManager:
    """Core Incident Management repository and qualification engine."""

    def __init__(self, triage_engine: Optional[IncidentTriageEngine] = None):
        self.incidents: Dict[str, Incident] = {}
        self.triage_engine = triage_engine or IncidentTriageEngine()

    def create_incident(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity = IncidentSeverity.HIGH,
        affected_assets: Optional[List[str]] = None,
        detections: Optional[List[str]] = None,
        owner: Optional[str] = None,
        tags: Optional[List[str]] = None,
        incident_id: Optional[str] = None
    ) -> Incident:
        inc_id = incident_id or f"INC-{uuid.uuid4().hex[:6].upper()}"
        inc = Incident(
            incident_id=inc_id,
            title=title,
            description=description,
            severity=severity,
            priority=IncidentPriority.P3_MEDIUM,
            status=IncidentStatus.NEW,
            affected_assets=affected_assets or [],
            detections=detections or [],
            owner=owner or "unassigned",
            tags=tags or ["security", "email-forensics"],
            sla_deadlines={
                "triage_by": time.time() + 900,        # 15m
                "contain_by": time.time() + 3600,      # 1h
                "remediate_by": time.time() + 14400,   # 4h
            }
        )
        inc.add_timeline_event(
            event_type="INCIDENT_CREATED",
            description=f"Incident {inc_id} qualified and created",
            actor="incident_manager",
            details={"severity": severity.value, "assets": inc.affected_assets}
        )
        self.incidents[inc_id] = inc

        # Automatically execute triage & priority assignment
        self.triage_engine.triage_incident(inc)
        PriorityEngine.calculate_priority(inc)
        IncidentLifecycleManager.transition(inc, IncidentStatus.TRIAGED, actor="incident_manager", reason="Initial triage completed")
        return inc

    def create_from_phase23_finding(self, finding: Any, case: Optional[Any] = None) -> Incident:
        """Converts a Phase 23 DetectionFinding or InvestigationCase into a qualified Incident."""
        finding_id = getattr(finding, "finding_id", "FINDING-UNKNOWN")
        rule_id = getattr(finding, "rule_id", "RULE-UNKNOWN")
        sev_str = getattr(finding, "severity", "HIGH")
        severity = IncidentSeverity[sev_str.upper()] if sev_str.upper() in IncidentSeverity.__members__ else IncidentSeverity.HIGH
        
        asset = getattr(finding, "asset", getattr(case, "target_entity", "MTA-07"))
        assets = [asset] if isinstance(asset, str) else list(asset)
        
        title = f"Suspicious Activity Detected: {rule_id} on {asset}"
        desc = getattr(finding, "rationale", getattr(case, "summary", "Autonomous threat detection finding qualified for response orchestration."))

        inc = self.create_incident(
            title=title,
            description=desc,
            severity=severity,
            affected_assets=assets,
            detections=[rule_id],
            tags=["phase23-detection", rule_id.lower()]
        )

        # Preserve evidence if available on finding
        evidence_dict = getattr(finding, "evidence", {})
        if evidence_dict:
            inc.add_evidence(
                evidence_type="SESSION",
                identifier=evidence_dict.get("session_id", "FLOW-001"),
                sha256="A" * 64,
                metadata=evidence_dict
            )
        return inc

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        priority: Optional[IncidentPriority] = None,
        severity: Optional[IncidentSeverity] = None
    ) -> List[Incident]:
        results = list(self.incidents.values())
        if status:
            results = [i for i in results if i.status == status]
        if priority:
            results = [i for i in results if i.priority == priority]
        if severity:
            results = [i for i in results if i.severity == severity]
        return results

    def reopen_incident(self, incident_id: str, new_evidence_desc: str) -> Incident:
        """Component 26: Automated reopening of an incident when recurrence is detected."""
        orig = self.incidents.get(incident_id)
        if not orig:
            raise KeyError(f"Incident {incident_id} not found")

        reopened_id = f"INC-REOPEN-{uuid.uuid4().hex[:4].upper()}"
        new_inc = self.create_incident(
            title=f"RECURRENCE: {orig.title}",
            description=f"Recurrence detected after resolution of {orig.incident_id}. New evidence: {new_evidence_desc}",
            severity=orig.severity,
            affected_assets=orig.affected_assets,
            detections=orig.detections,
            incident_id=reopened_id
        )
        new_inc.linked_incident_id = orig.incident_id
        orig.reopened_count += 1
        new_inc.reopened_count = orig.reopened_count
        new_inc.status = IncidentStatus.REOPENED

        orig.add_timeline_event(
            event_type="INCIDENT_REOPENED",
            description=f"Incident reopened as {new_inc.incident_id} due to recurrence detection.",
            actor="recurrence_watcher",
            details={"new_incident_id": new_inc.incident_id, "evidence": new_evidence_desc}
        )
        return new_inc
