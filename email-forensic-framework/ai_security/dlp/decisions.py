"""AI DLP Decisions and Outcomes.
Component 30.13 & 30.61: Structured, explainable decision records for AI data loss prevention events.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AIDLPAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    WARN = "WARN"
    REDACT = "REDACT"
    RESTRICT = "RESTRICT"
    BLOCK = "BLOCK"


@dataclass
class AIDLPDecision:
    decision_id: str
    event_id: str
    action: AIDLPAction
    matched_policy_id: Optional[str]
    reasons: List[str]
    source_asset_id: str
    caller_agent_id: str
    destination: str
    confidence: float
    is_blocked: bool
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "event_id": self.event_id,
            "action": self.action.value,
            "matched_policy_id": self.matched_policy_id,
            "reasons": self.reasons,
            "source_asset_id": self.source_asset_id,
            "caller_agent_id": self.caller_agent_id,
            "destination": self.destination,
            "confidence": self.confidence,
            "is_blocked": self.is_blocked,
            "evaluated_at": self.evaluated_at,
        }
