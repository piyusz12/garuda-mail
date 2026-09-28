"""
Phase 24 — Automated Incident Reopening (Component 26)
Triggers automated reopening when post-incident watchers detect recurring security anomalies.
"""

from typing import Dict, List, Any, Optional
from incident.models import Incident, IncidentStatus
from incident.manager import IncidentManager


class AutoReopenManager:
    """Manages the linkage between original resolved incidents and new reopened incidents."""

    def __init__(self, incident_manager: IncidentManager):
        self.incident_manager = incident_manager

    def handle_recurrence_event(self, recurrence_event: Dict[str, Any]) -> Incident:
        orig_id = recurrence_event["incident_id"]
        evidence_desc = f"Recurrence alert triggered on asset {recurrence_event['asset_id']} matching watcher {recurrence_event['watcher_id']}"
        reopened_incident = self.incident_manager.reopen_incident(orig_id, evidence_desc)
        return reopened_incident
