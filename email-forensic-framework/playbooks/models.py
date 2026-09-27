"""
Phase 24 — Response Playbooks Models (Components 4, 36, 56)
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class PlaybookMaturity(str, Enum):
    MANUAL = "MANUAL"
    ASSISTED = "ASSISTED"
    APPROVAL_DRIVEN = "APPROVAL_DRIVEN"
    CANARY_AUTOMATION = "CANARY_AUTOMATION"
    AUTOMATED = "AUTOMATED"
    ADAPTIVE = "ADAPTIVE"


@dataclass
class PlaybookStep:
    step_id: str
    sequence: int
    name: str
    phase: str  # INVESTIGATION, CONTAINMENT, REMEDIATION, VERIFICATION, ROLLBACK
    action_name: str
    description: str
    required_approval: bool = False
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    playbook_id: str
    name: str
    version: str
    maturity: PlaybookMaturity
    trigger: str
    preconditions: List[str]
    investigation_steps: List[PlaybookStep]
    containment_steps: List[PlaybookStep]
    remediation_steps: List[PlaybookStep]
    verification_steps: List[PlaybookStep]
    rollback_steps: List[PlaybookStep]
    closure_conditions: List[str]
    historical_rollback_rate: float = 0.0
    execution_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
