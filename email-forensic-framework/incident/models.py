"""
Phase 24 — Incident Management Models
Defines Core Incident entities, enums, lifecycles, and data contracts.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"
    RECOVERY = "RECOVERY"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    WAITING_EXTERNAL = "WAITING_EXTERNAL"
    ROLLBACK = "ROLLBACK"
    REOPENED = "REOPENED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentPriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


@dataclass
class IncidentTimelineEntry:
    entry_id: str
    timestamp: float
    iso_time: str
    event_type: str
    description: str
    actor: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentEvidence:
    evidence_id: str
    evidence_type: str  # PCAP, SESSION, CERTIFICATE, JA4, CONFIG_SNAPSHOT, LOG
    identifier: str
    sha256: str
    collected_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    priority: IncidentPriority
    status: IncidentStatus
    affected_assets: List[str]
    detections: List[str] = field(default_factory=list)
    evidence: List[IncidentEvidence] = field(default_factory=list)
    owner: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    triage_data: Dict[str, Any] = field(default_factory=dict)
    response_plan_id: Optional[str] = None
    linked_incident_id: Optional[str] = None
    timeline: List[IncidentTimelineEntry] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    reopened_count: int = 0
    sla_deadlines: Dict[str, float] = field(default_factory=dict)

    def add_timeline_event(self, event_type: str, description: str, actor: str = "system", details: Optional[Dict[str, Any]] = None):
        now = time.time()
        iso = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))
        entry = IncidentTimelineEntry(
            entry_id=f"EVT-{uuid.uuid4().hex[:6].upper()}",
            timestamp=now,
            iso_time=iso,
            event_type=event_type,
            description=description,
            actor=actor,
            details=details or {}
        )
        self.timeline.append(entry)
        self.updated_at = now
        return entry

    def add_evidence(self, evidence_type: str, identifier: str, sha256: str, metadata: Optional[Dict[str, Any]] = None):
        ev = IncidentEvidence(
            evidence_id=f"EV-{uuid.uuid4().hex[:6].upper()}",
            evidence_type=evidence_type,
            identifier=identifier,
            sha256=sha256,
            collected_at=time.time(),
            metadata=metadata or {}
        )
        self.evidence.append(ev)
        self.updated_at = time.time()
        return ev

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
