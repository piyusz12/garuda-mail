"""
Phase 24 — Incident Timeline Synthesizer (Component 27)
Builds immutable, ordered chronological timelines from incident lifecycle events.
"""

from typing import Dict, List, Any
from incident.models import Incident


class TimelineAuditor:
    """Renders formatted chronological audit trails of incident milestones."""

    @classmethod
    def render_ascii_timeline(cls, incident: Incident) -> str:
        lines = [
            f"=== INCIDENT TIMELINE: {incident.incident_id} ===",
            f"Title: {incident.title}",
            f"Severity: {incident.severity.value} | Priority: {incident.priority.value} | Status: {incident.status.value}",
            "--------------------------------------------------------------------------------",
            f"{'Timestamp (UTC)':<20} | {'Actor':<15} | {'Event':<22} | {'Description'}",
            "--------------------------------------------------------------------------------"
        ]

        for e in incident.timeline:
            lines.append(f"{e.iso_time:<20} | {e.actor:<15} | {e.event_type:<22} | {e.description}")

        lines.append("--------------------------------------------------------------------------------")
        return "\n".join(lines)
