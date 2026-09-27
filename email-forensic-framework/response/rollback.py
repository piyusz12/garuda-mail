"""
Phase 24 — Rollback Engine & State Machine (Components 22, 29)
Manages safe reversal of actions upon execution failure or verification failure.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time

from response.actions import ResponseAction, ActionStatus, ActionResult


class RollbackState(str, Enum):
    IDLE = "IDLE"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


@dataclass
class RollbackExecutionRecord:
    rollback_id: str
    action_id: str
    target_asset: str
    rollback_command: str
    state: RollbackState
    started_at: float
    completed_at: float
    success: bool
    output: str
    error: Optional[str] = None


class RollbackEngine:
    """Orchestrates structured rollbacks in reverse order when canary or verification fails."""

    def __init__(self):
        self.rollback_records: List[RollbackExecutionRecord] = []

    def rollback_action(self, action: ResponseAction, connector_registry: Any, reason: str = "") -> RollbackExecutionRecord:
        """Executes the rollback command for a single action via its connector."""
        started = time.time()
        record_id = f"RBK-{action.action_id}"

        if not action.rollback_command:
            record = RollbackExecutionRecord(
                rollback_id=record_id,
                action_id=action.action_id,
                target_asset=action.target_asset,
                rollback_command="",
                state=RollbackState.FAILED,
                started_at=started,
                completed_at=time.time(),
                success=False,
                output="",
                error="Action does not define a rollback_command."
            )
            self.rollback_records.append(record)
            return record

        try:
            connector = connector_registry.get_connector_for_type(action.action_type)
            result = connector.rollback(action)
            success = result.success
            state = RollbackState.COMPLETED if success else RollbackState.FAILED
            output = result.output_message
            err = result.error
        except Exception as e:
            success = False
            state = RollbackState.ESCALATED
            output = ""
            err = str(e)

        record = RollbackExecutionRecord(
            rollback_id=record_id,
            action_id=action.action_id,
            target_asset=action.target_asset,
            rollback_command=action.rollback_command,
            state=state,
            started_at=started,
            completed_at=time.time(),
            success=success,
            output=output,
            error=err
        )
        if success:
            action.status = ActionStatus.ROLLED_BACK
        self.rollback_records.append(record)
        return record

    def rollback_plan(self, executed_actions: List[ResponseAction], connector_registry: Any, reason: str = "") -> List[RollbackExecutionRecord]:
        """Rolls back a list of completed actions in strict reverse chronological order."""
        records = []
        for action in reversed(executed_actions):
            if action.status == ActionStatus.SUCCESS:
                rec = self.rollback_action(action, connector_registry, reason=reason)
                records.append(rec)
        return records
