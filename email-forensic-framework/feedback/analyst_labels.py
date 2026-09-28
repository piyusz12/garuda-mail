"""
Phase 23 - Analyst Feedback Loop.
Collects and tracks human analyst verdicts with reviewer confidence and authority weighting.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import uuid

@dataclass
class AnalystFeedbackRecord:
    feedback_id: str
    finding_id: str
    detection_id: str
    verdict: str  # CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, DUPLICATE
    analyst_id: str
    analyst_authority: float = 0.90  # 0.0 - 1.0 (Tier 1 vs Lead Principal)
    reason: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class AnalystFeedbackCollector:
    """Manages ground-truth feedback signals from human investigators."""

    def __init__(self):
        self.records: Dict[str, AnalystFeedbackRecord] = {}

    def record_feedback(
        self,
        finding_id: str,
        detection_id: str,
        verdict: str,
        analyst_id: str,
        reason: str,
        context: Optional[Dict[str, Any]] = None,
        authority: float = 0.90
    ) -> AnalystFeedbackRecord:
        fb_id = f"FB-{uuid.uuid4().hex[:6].upper()}"
        rec = AnalystFeedbackRecord(
            feedback_id=fb_id,
            finding_id=finding_id,
            detection_id=detection_id,
            verdict=verdict.upper(),
            analyst_id=analyst_id,
            analyst_authority=authority,
            reason=reason,
            context=context or {}
        )
        self.records[fb_id] = rec
        return rec

    def get_feedback_for_detection(self, detection_id: str) -> List[AnalystFeedbackRecord]:
        return [r for r in self.records.values() if r.detection_id == detection_id]
