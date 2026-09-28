"""
Phase 23 - Detection Engineering Models
Defines detection rules, severity dimensions, and finding lifecycle structures.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import uuid

@dataclass
class SeverityDimensions:
    """Explicit severity dimensions decomposing threat score."""
    impact: float = 0.5       # 0.0 - 1.0
    exposure: float = 0.5     # 0.0 - 1.0
    confidence: float = 0.5   # 0.0 - 1.0
    persistence: float = 0.5  # 0.0 - 1.0
    scope: float = 0.5        # 0.0 - 1.0

    def calculate_score(self) -> float:
        """Computes weighted aggregate score."""
        weights = {"impact": 0.30, "exposure": 0.20, "confidence": 0.25, "persistence": 0.15, "scope": 0.10}
        score = (
            self.impact * weights["impact"] +
            self.exposure * weights["exposure"] +
            self.confidence * weights["confidence"] +
            self.persistence * weights["persistence"] +
            self.scope * weights["scope"]
        )
        return round(score, 3)

    def to_qualitative(self) -> str:
        score = self.calculate_score()
        if score >= 0.80:
            return "CRITICAL"
        elif score >= 0.60:
            return "HIGH"
        elif score >= 0.40:
            return "MEDIUM"
        return "LOW"


@dataclass
class DetectionRule:
    """Detection rule entity with software-style lifecycle & versioning."""
    detection_id: str
    name: str
    description: str
    logic: Dict[str, Any]
    rule_type: str = "SIGNATURE"  # SIGNATURE, THRESHOLD, SEQUENCE, ANOMALY, STATISTICAL, BEHAVIORAL, GRAPH, ML
    severity: str = "MEDIUM"
    severity_dimensions: SeverityDimensions = field(default_factory=SeverityDimensions)
    confidence: float = 0.8
    data_sources: List[str] = field(default_factory=lambda: ["tls_events"])
    attack_techniques: List[str] = field(default_factory=list)
    version: str = "1.0"
    owner: str = "detection-engineering"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "DRAFT"  # DRAFT, TESTING, VALIDATED, STAGING, CANARY, PRODUCTION, DEPRECATED
    canary_target_assets: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A cluster-deduplicated security finding created by detections or hunts."""
    finding_id: str
    detection_id: str
    asset_id: str
    timestamp: datetime
    severity: str
    confidence: float
    confidence_breakdown: Dict[str, float] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    status: str = "NEW"  # NEW, TRIAGED, INVESTIGATING, CONFIRMED, REMEDIATED, MONITORING, RESOLVED, FALSE_POSITIVE, DUPLICATE, ACCEPTED_RISK, REOPENED
    details: Dict[str, Any] = field(default_factory=dict)
    explanation: List[str] = field(default_factory=list)
    remediation_watcher_active: bool = False
    remediation_date: Optional[datetime] = None
    recurrence_count: int = 0
    analyst_verdict: Optional[str] = None
    analyst_notes: Optional[str] = None
