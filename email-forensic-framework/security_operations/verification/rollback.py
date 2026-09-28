"""
Phase 25 — Automated Rollback Engine
Reverts applied changes to pre-execution snapshots upon verification failure or manual override.
"""

from typing import Dict, Any, Optional
from ..actions.registry import ActionRecord, ActionState
from ..actions.executor import ActionExecutor


class RollbackEngine:
    """Manages automatic or requested rollback of reversible actions."""

    def __init__(self, action_executor: Optional[ActionExecutor] = None):
        self.executor = action_executor or ActionExecutor()

    def execute_rollback(
        self,
        action: ActionRecord,
        reason: str = "Verification failed",
        actor: str = "orchestrator",
    ) -> Dict[str, Any]:
        """Rolls back the target action using its associated adapter."""
        if not action.snapshot_before:
            return {
                "status": "NOT_REVERSIBLE",
                "message": "Action has no stored pre-execution snapshot.",
                "action_id": action.action_id,
            }

        try:
            adapter = self.executor._get_adapter(action.action_type)
            result = adapter.rollback(action)
            action.transition_to(ActionState.ROLLED_BACK)
            return {
                "status": "ROLLED_BACK",
                "action_id": action.action_id,
                "reason": reason,
                "actor": actor,
                "result": result,
            }
        except Exception as e:
            return {
                "status": "ROLLBACK_ERROR",
                "action_id": action.action_id,
                "error": str(e),
            }
