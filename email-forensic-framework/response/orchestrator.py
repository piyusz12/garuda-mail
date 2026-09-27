"""
Phase 24 — Action Orchestrator (Components 10, 19, 46, 66, 67)
Executes response plans, enforces concurrency change locks, idempotency checks, and handles partial rollout failures.
"""

from typing import Dict, List, Optional, Any, Set
import time

from incident.models import Incident, IncidentStatus
from incident.lifecycle import IncidentLifecycleManager
from response.actions import ResponseAction, ActionStatus, ActionResult
from response.planner import ResponsePlan, PlanStatus
from response.rollback import RollbackEngine


class ConcurrencyLockError(Exception):
    pass


class ActionOrchestrator:
    """Manages active change locks, dispatches actions to connectors, and monitors rollout integrity."""

    def __init__(self, connector_registry: Any, rollback_engine: Optional[RollbackEngine] = None):
        self.connector_registry = connector_registry
        self.rollback_engine = rollback_engine or RollbackEngine()
        self.asset_locks: Dict[str, str] = {}  # asset_id -> lock_owner (e.g. plan_id)
        self.executed_idempotency_keys: Dict[str, ActionResult] = {}

    def acquire_locks(self, plan: ResponsePlan, assets: List[str]) -> bool:
        """Component 67: Concurrency change locks to prevent race conditions across operators & automation."""
        conflicts = [a for a in assets if a in self.asset_locks and self.asset_locks[a] != plan.plan_id]
        if conflicts:
            raise ConcurrencyLockError(
                f"Cannot execute plan {plan.plan_id}: Assets currently locked by other changes: {conflicts}"
            )
        for a in assets:
            self.asset_locks[a] = plan.plan_id
        return True

    def release_locks(self, plan: ResponsePlan, assets: List[str]):
        for a in assets:
            if self.asset_locks.get(a) == plan.plan_id:
                del self.asset_locks[a]

    def execute_plan(
        self,
        plan: ResponsePlan,
        incident: Incident,
        stop_on_failure: bool = True
    ) -> ResponsePlan:
        """Executes actions in sequence across canary stages."""
        plan.status = PlanStatus.EXECUTING
        IncidentLifecycleManager.transition(
            incident,
            IncidentStatus.REMEDIATION,
            actor="orchestrator",
            reason=f"Executing response plan {plan.plan_id}"
        )

        all_assets = list({a.target_asset for a in plan.actions if a.target_asset})
        self.acquire_locks(plan, all_assets)

        completed_actions: List[ResponseAction] = []
        has_failure = False

        try:
            for action in plan.actions:
                # Component 66: Idempotency check
                if action.idempotency_key in self.executed_idempotency_keys:
                    prev_res = self.executed_idempotency_keys[action.idempotency_key]
                    action.result = prev_res
                    action.status = prev_res.status
                    incident.add_timeline_event(
                        event_type="ACTION_IDEMPOTENT_SKIP",
                        description=f"Action '{action.name}' skipped: previously executed under key {action.idempotency_key}",
                        actor="orchestrator"
                    )
                    completed_actions.append(action)
                    continue

                action.status = ActionStatus.RUNNING
                started = time.time()
                try:
                    connector = self.connector_registry.get_connector_for_type(action.action_type)
                    res = connector.execute(action)
                    action.result = res
                    action.status = ActionStatus.SUCCESS if res.success else ActionStatus.FAILED
                except Exception as e:
                    res = ActionResult(
                        action_id=action.action_id,
                        status=ActionStatus.FAILED,
                        started_at=started,
                        completed_at=time.time(),
                        success=False,
                        output_message="",
                        error=str(e),
                        execution_time_ms=(time.time() - started) * 1000
                    )
                    action.result = res
                    action.status = ActionStatus.FAILED

                self.executed_idempotency_keys[action.idempotency_key] = res
                completed_actions.append(action)

                incident.add_timeline_event(
                    event_type=f"ACTION_{action.status.value}",
                    description=f"Action '{action.name}' on {action.target_asset}: {action.status.value}",
                    actor="orchestrator",
                    details={"action_id": action.action_id, "output": res.output_message, "error": res.error}
                )

                if action.status == ActionStatus.FAILED:
                    has_failure = True
                    if stop_on_failure:
                        break

            # Handle Partial Failures (Component 46) & Rollback (Component 22)
            if has_failure:
                plan.status = PlanStatus.FAILED
                incident.add_timeline_event(
                    event_type="ROLLOUT_PARTIAL_FAILURE",
                    description=f"Plan {plan.plan_id} encountered execution failure. Triggering automated rollback.",
                    actor="orchestrator"
                )
                IncidentLifecycleManager.transition(
                    incident,
                    IncidentStatus.ROLLBACK,
                    actor="orchestrator",
                    reason="Automated rollback due to action execution failure."
                )
                self.rollback_engine.rollback_plan(completed_actions, self.connector_registry, reason="Action execution failure")
                plan.status = PlanStatus.ROLLED_BACK
            else:
                plan.status = PlanStatus.COMPLETED
                plan.completed_at = time.time()
                incident.add_timeline_event(
                    event_type="RESPONSE_PLAN_EXECUTED",
                    description=f"All {len(plan.actions)} actions in plan {plan.plan_id} executed successfully.",
                    actor="orchestrator"
                )

        finally:
            self.release_locks(plan, all_assets)

        return plan
