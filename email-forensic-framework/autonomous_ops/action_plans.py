"""Garuda Phase 35: Module J - Structured Action Plans & Pipeline.
Generates typed, explainable operational action proposals with risk ratings and rollback plans.
"""
from typing import Dict, List, Optional, Any
import time
import uuid

from autonomous_ops.models import ActionPlan, ActionRiskLevel, ActionExecutionStatus
from autonomous_ops.governance_bridge import AutonomyGovernanceBridge


class ActionPlanManager:
    """Creates, queries, and tracks lifecycle of operational action proposals."""

    def __init__(self, governance_bridge: AutonomyGovernanceBridge):
        self.governance_bridge = governance_bridge
        self._action_plans: Dict[str, ActionPlan] = {}
        self._seed_sample_plans()

    def create_action_plan(
        self,
        action_type: str,
        target_resource: str,
        reason: str,
        risk_level: ActionRiskLevel = ActionRiskLevel.LOW,
        reversible: bool = True,
        expected_effect: str = "Reduce latency and balance resource consumption",
        rollback_plan: str = "Revert target state to prior snapshot",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ActionPlan:
        """Constructs a validated action plan."""
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        plan = ActionPlan(
            action_id=action_id,
            action_type=action_type,
            target_resource=target_resource,
            reason=reason,
            risk_level=risk_level,
            reversible=reversible,
            approval_required=False,
            expected_effect=expected_effect,
            rollback_plan=rollback_plan,
            parameters=parameters or {},
        )

        # Evaluate against governance bridge
        permitted, decision_reason, requires_approval = self.governance_bridge.evaluate_action_permission(plan)
        plan.approval_required = requires_approval
        plan.policy_decision = "ALLOW" if permitted else "DENY"

        if not permitted:
            plan.status = ActionExecutionStatus.REJECTED
            plan.error = decision_reason
        elif requires_approval:
            plan.status = ActionExecutionStatus.PENDING_APPROVAL
        else:
            plan.status = ActionExecutionStatus.APPROVED

        self._action_plans[action_id] = plan
        return plan

    def get_plan(self, action_id: str) -> Optional[ActionPlan]:
        return self._action_plans.get(action_id)

    def list_plans(self, status: Optional[ActionExecutionStatus] = None) -> List[ActionPlan]:
        plans = list(self._action_plans.values())
        if status:
            plans = [p for p in plans if p.status == status]
        plans.sort(key=lambda p: p.created_at, reverse=True)
        return plans

    def approve_plan(self, action_id: str, admin_id: str = "admin@garuda.internal") -> ActionPlan:
        """Administrator approves a pending action plan."""
        plan = self._action_plans.get(action_id)
        if not plan:
            raise ValueError(f"Action plan '{action_id}' not found")
        if plan.status != ActionExecutionStatus.PENDING_APPROVAL:
            raise ValueError(f"Action plan '{action_id}' is not awaiting approval (Current: {plan.status.value})")

        plan.approved_by = admin_id
        plan.status = ActionExecutionStatus.APPROVED
        return plan

    def _seed_sample_plans(self):
        plan1 = self.create_action_plan(
            action_type="reroute_eligible_job",
            target_resource="JOB-829",
            reason="Primary worker NODE-002 experiencing queue saturation",
            risk_level=ActionRiskLevel.LOW,
            expected_effect="Reroute job to NODE-001 with lower latency",
            rollback_plan="Return job to original queue",
        )
        plan2 = self.create_action_plan(
            action_type="quarantine_worker",
            target_resource="NODE-004-QUARANTINED",
            reason="Repeated policy and air-gapped egress violations observed",
            risk_level=ActionRiskLevel.HIGH,
            expected_effect="Isolate rogue worker from receiving sensitive compute",
            rollback_plan="Re-verify worker integrity and restore trust level",
        )
