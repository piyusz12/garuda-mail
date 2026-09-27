"""
Phase 23 - Forensic Case Automation and Management.
Packages validated evidence and hypotheses into actionable security cases.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import uuid

@dataclass
class ForensicCase:
    case_id: str
    title: str
    summary: str
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    detections: List[str] = field(default_factory=list)
    hypotheses: List[str] = field(default_factory=list)
    counter_evidence: List[str] = field(default_factory=list)
    recommended_next_steps: List[str] = field(default_factory=list)
    status: str = "OPEN"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CaseManager:
    """Automates creation and tracking of forensic investigation cases."""

    def __init__(self):
        self.cases: Dict[str, ForensicCase] = {}

    def create_case(
        self,
        title: str,
        summary: str,
        timeline: List[Dict[str, Any]],
        entities: Dict[str, Any],
        evidence: List[str],
        detections: List[str],
        hypotheses: List[str],
        counter_evidence: List[str],
        recommended_next_steps: Optional[List[str]] = None
    ) -> ForensicCase:
        case_id = f"CASE-{uuid.uuid4().hex[:6].upper()}"
        case = ForensicCase(
            case_id=case_id,
            title=title,
            summary=summary,
            timeline=timeline,
            entities=entities,
            evidence=evidence,
            detections=detections,
            hypotheses=hypotheses,
            counter_evidence=counter_evidence,
            recommended_next_steps=recommended_next_steps or [
                "Review certificate deployment records with infrastructure team.",
                "Verify peer MTA configurations for identical JA4 fingerprints.",
                "Ensure STARTTLS strict enforcement via DANE / MTA-STS."
            ]
        )
        self.cases[case_id] = case
        return case

    def get_case(self, case_id: str) -> Optional[ForensicCase]:
        return self.cases.get(case_id)

    def list_cases(self) -> List[ForensicCase]:
        return list(self.cases.values())
