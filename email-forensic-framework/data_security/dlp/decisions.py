"""
Data Loss Prevention (DLP) Decision Outcomes.
Component 29.31: Decision models including ALLOW, MONITOR, WARN, RESTRICT, and BLOCK.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class DLPAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    WARN = "WARN"
    STEP_UP = "STEP_UP"
    RESTRICT = "RESTRICT"
    BLOCK = "BLOCK"


@dataclass
class DLPDecisionRecord:
    decision_id: str
    event_id: str
    asset_id: str
    action: DLPAction
    matched_policy_id: Optional[str]
    reasons: List[str]
    confidence: float
    is_blocked: bool
    enforced_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "event_id": self.event_id,
            "asset_id": self.asset_id,
            "action": self.action.value,
            "matched_policy_id": self.matched_policy_id,
            "reasons": self.reasons,
            "confidence": self.confidence,
            "is_blocked": self.is_blocked,
            "enforced_at": self.enforced_at,
        }
