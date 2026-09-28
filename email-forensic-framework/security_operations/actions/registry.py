"""
Phase 25 — Action Risk Classification & Registry
Registers available response actions, risk levels (R0-R4), and state transitions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class ActionRiskClass(str, Enum):
    R0_READ_ONLY = "R0_READ_ONLY"                   # Telemetry, PCAP, config inspection
    R1_NON_DISRUPTIVE = "R1_NON_DISRUPTIVE"         # Minor logging, alert notification, ticket update
    R2_LIMITED_REVERSIBLE = "R2_LIMITED_REVERSIBLE" # Bounded temporary firewall quarantine (30m)
    R3_POTENTIAL_IMPACT = "R3_POTENTIAL_IMPACT"     # Legacy TLS disablement on single MTA, cert rotation
    R4_MAJOR_CRITICAL = "R4_MAJOR_CRITICAL"         # Fleetwide crypto change, host isolation, CA revocation


class ActionState(str, Enum):
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    VERIFIED = "VERIFIED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class ActionRecord:
    action_id: str
    case_id: str
    action_type: str
    target: str
    risk_class: ActionRiskClass
    state: ActionState = ActionState.REQUESTED
    idempotency_key: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    state_history: List[str] = field(default_factory=list)
    snapshot_before: Optional[Dict[str, Any]] = None
    snapshot_after: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def transition_to(self, new_state: ActionState):
        self.state = new_state
        self.state_history.append(new_state.value)
        self.updated_at = time.time()


class ActionRegistry:
    """Manages active action records and action catalog definitions."""

    def __init__(self):
        self._actions: Dict[str, ActionRecord] = {}

    def register_action(
        self,
        case_id: str,
        action_type: str,
        target: str,
        risk_class: ActionRiskClass,
        parameters: Optional[Dict[str, Any]] = None,
        idempotency_key: str = "",
    ) -> ActionRecord:
        aid = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        rec = ActionRecord(
            action_id=aid,
            case_id=case_id,
            action_type=action_type,
            target=target,
            risk_class=risk_class,
            parameters=parameters or {},
            idempotency_key=idempotency_key,
            state_history=[ActionState.REQUESTED.value],
        )
        self._actions[aid] = rec
        return rec

    def get_action(self, action_id: str) -> Optional[ActionRecord]:
        return self._actions.get(action_id)

    def list_actions(self, case_id: Optional[str] = None) -> List[ActionRecord]:
        if case_id:
            return [a for a in self._actions.values() if a.case_id == case_id]
        return list(self._actions.values())
