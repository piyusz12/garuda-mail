"""AI Incident Chronological Timeline Builder.
Components 30.39, 30.54, 30.81: Correlates agent start, retrieval, tool calls, DLP blocks, and containment actions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class AITimelineEntry:
    time_str: str
    epoch_timestamp: float
    event_category: str  # "AGENT", "RAG", "DATABASE", "TOOL", "DLP", "RESPONSE", "FORENSICS"
    summary: str
    actor: str
    evidence_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time_str": self.time_str,
            "epoch_timestamp": self.epoch_timestamp,
            "event_category": self.event_category,
            "summary": self.summary,
            "actor": self.actor,
            "evidence_ref": self.evidence_ref,
        }


class AITimelineBuilder:
    """Builds chronological forensic timelines matching Section 30.81."""

    @classmethod
    def build_incident_timeline(
        cls,
        agent_id: str = "AGENT-41",
        model_id: str = "MODEL-781",
        destination: str = "external.example",
    ) -> List[AITimelineEntry]:
        now = time.time()
        return [
            AITimelineEntry("14:21:00", now - 600, "AGENT", f"Autonomous agent {agent_id} initialized under identity SERVICE-IDENTITY-77", agent_id, "K8S-POD-START"),
            AITimelineEntry("14:21:02", now - 480, "RAG", "Agent initiated semantic vector retrieval against VECTOR-DB-07 (kb-customer-docs)", agent_id, "VDB-QUERY-991"),
            AITimelineEntry("14:21:03", now - 420, "RAG", "Restricted customer metadata chunk retrieved into agent context", "VECTOR-DB-07", "DOC-CHUNK-8821"),
            AITimelineEntry("14:21:04", now - 360, "DATABASE", "Database tool executed bulk query against PostgreSQL customer vault", "database_query", "SQL-LOG-441"),
            AITimelineEntry("14:21:05", now - 300, "TOOL", f"HTTP tool invoked targeting outbound destination {destination}", "http_post", "TOOL-CALL-88"),
            AITimelineEntry("14:21:05", now - 299, "DLP", "AI DLP engine detected RESTRICTED customer data payload in outbound HTTP request", "AI-DLP-Engine", "DLP-ALERT-91"),
            AITimelineEntry("14:21:05", now - 298, "RESPONSE", "Outbound external transfer severed and blocked under policy AI-DLP-01", "DLP-Enforcer", "BLOCK-DEC-01"),
            AITimelineEntry("14:21:06", now - 240, "RESPONSE", f"Containment activated: HTTP tool revoked for {agent_id}; database & RAG kept available", "SOC-Engine", "CASE-9001"),
            AITimelineEntry("14:21:10", now, "FORENSICS", "Immutable cryptographic forensic snapshot and evidence package compiled", "Forensic-Manager", "AISNAP-VERIFY"),
        ]
