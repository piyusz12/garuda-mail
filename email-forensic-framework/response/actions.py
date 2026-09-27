"""
Phase 24 — Response Actions & Execution Contracts (Components 10, 11, 12, 13, 14, 15, 66)
Defines granular response actions with idempotency keys, forward & rollback specifications, and execution results.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import hashlib
import json
import time
import uuid

from response.risk import ActionRiskClass


class ActionType(str, Enum):
    NETWORK = "NETWORK"            # Block IP/CIDR, block JA4, ACL change, bounded quarantine
    ENDPOINT = "ENDPOINT"          # Collect evidence, isolate host, stop process
    IDENTITY = "IDENTITY"          # Revoke session, force re-auth, expire credential
    CERTIFICATE = "CERTIFICATE"    # Rotate cert, revoke compromised cert, deploy replacement
    CRYPTOGRAPHIC = "CRYPTOGRAPHIC"# Disable legacy TLS, remove weak cipher, enforce PFS
    TICKETING = "TICKETING"        # Create/update ServiceNow/Jira change ticket
    NOTIFICATION = "NOTIFICATION"  # Notify SOC, PKI team, asset owner, executive alert


class ActionStatus(str, Enum):
    PENDING = "PENDING"
    SIMULATING = "SIMULATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SKIPPED = "SKIPPED"


@dataclass
class ActionResult:
    action_id: str
    status: ActionStatus
    started_at: float
    completed_at: float
    success: bool
    output_message: str
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0


@dataclass
class ResponseAction:
    action_id: str
    sequence: int
    name: str
    action_type: ActionType
    target_asset: str
    parameters: Dict[str, Any]
    risk_class: ActionRiskClass
    idempotency_key: str
    forward_command: str
    rollback_command: str
    verification_spec: Dict[str, Any]
    status: ActionStatus = ActionStatus.PENDING
    created_at: float = field(default_factory=time.time)
    result: Optional[ActionResult] = None
    config_before: Optional[Dict[str, Any]] = None
    config_after: Optional[Dict[str, Any]] = None
    duration_minutes: Optional[int] = None  # For bounded temporary containments

    def compute_action_hash(self) -> str:
        """Computes cryptographic SHA-256 hash of action payload for approval verification."""
        canonical = {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target_asset": self.target_asset,
            "parameters": self.parameters,
            "forward_command": self.forward_command,
            "rollback_command": self.rollback_command,
            "risk_class": self.risk_class.value,
            "idempotency_key": self.idempotency_key
        }
        raw = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
