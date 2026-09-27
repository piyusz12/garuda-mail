"""
Phase 24 — Incident Priority Engine
Calculates multi-dimensional operational priority (P1 to P4) using severity, confidence, criticality, scope, and recurrence.
"""

from typing import Dict, Any, Tuple
from incident.models import Incident, IncidentPriority, IncidentSeverity


class PriorityEngine:
    """Computes operational priority score and assigns P1/P2/P3/P4 with full justification."""

    SEVERITY_WEIGHTS = {
        IncidentSeverity.CRITICAL: 40.0,
        IncidentSeverity.HIGH: 30.0,
        IncidentSeverity.MEDIUM: 15.0,
        IncidentSeverity.LOW: 5.0,
        IncidentSeverity.INFO: 0.0,
    }

    CRITICALITY_WEIGHTS = {
        "CRITICAL": 30.0,
        "HIGH": 20.0,
        "MEDIUM": 10.0,
        "LOW": 2.0,
    }

    @classmethod
    def calculate_priority(cls, incident: Incident) -> Tuple[IncidentPriority, Dict[str, Any]]:
        triage = incident.triage_data or {}
        
        # Dimension 1: Severity score (0 - 40)
        sev_score = cls.SEVERITY_WEIGHTS.get(incident.severity, 15.0)

        # Dimension 2: Asset Criticality score (0 - 30)
        crit_label = triage.get("asset_criticality", "MEDIUM")
        crit_score = cls.CRITICALITY_WEIGHTS.get(crit_label, 10.0)

        # Dimension 3: Confidence factor (0.5 to 1.0)
        confidence = float(triage.get("confidence", 0.85))

        # Dimension 4: Scope impact (0 - 15)
        scope_ratio = float(triage.get("scope_ratio", 0.2))
        scope_score = min(15.0, scope_ratio * 15.0)

        # Dimension 5: Recurrence multiplier (0 - 15)
        recurrence = bool(triage.get("historical_recurrence", False))
        recurrence_score = 15.0 if recurrence else 0.0

        # Raw total: 0 - 100
        raw_score = (sev_score + crit_score + scope_score + recurrence_score) * confidence

        # Map to P1 - P4
        if raw_score >= 70.0 or (incident.severity == IncidentSeverity.CRITICAL and crit_label in ["CRITICAL", "HIGH"]):
            priority = IncidentPriority.P1_CRITICAL
        elif raw_score >= 50.0:
            priority = IncidentPriority.P2_HIGH
        elif raw_score >= 30.0:
            priority = IncidentPriority.P3_MEDIUM
        else:
            priority = IncidentPriority.P4_LOW

        breakdown = {
            "calculated_score": round(raw_score, 2),
            "severity_component": sev_score,
            "asset_criticality_component": crit_score,
            "scope_component": round(scope_score, 2),
            "recurrence_component": recurrence_score,
            "confidence_multiplier": confidence,
            "assigned_priority": priority.value,
            "rationale": f"Score {raw_score:.1f} based on {incident.severity.value} severity, {crit_label} assets, {scope_ratio*100:.0f}% scope, recurrence={recurrence}"
        }

        incident.priority = priority
        incident.add_timeline_event(
            event_type="PRIORITY_ASSIGNED",
            description=f"Assigned priority {priority.value} (Score: {raw_score:.1f})",
            actor="priority_engine",
            details=breakdown
        )
        return priority, breakdown
