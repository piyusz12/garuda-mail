"""Garuda Phase 35: Module I - Bounded Autonomy & Action Governance.
Enforces autonomy execution modes (Observe, Recommend & Approve, Bounded Automation)
and guarantees that no autonomous action can bypass Phase 33 policies.
"""
from typing import Dict, List, Optional, Any, Set
from autonomous_ops.models import AutonomyMode, ActionPlan, ActionRiskLevel


class AutonomyGovernanceBridge:
    """Evaluates proposed operational actions against allowlists, risk budgets, and Phase 33 governance."""

    # Explicit allowlists (Section 35.11)
    ALLOWED_AUTOMATIC_ACTIONS: Set[str] = {
        "health_check",
        "mark_worker_unhealthy",
        "reroute_eligible_job",
        "retry_idempotent_job",
        "apply_queue_backpressure",
        "prewarm_approved_model",
        "prewarm_model",
        "unload_idle_model",
        "evict_idle_cache",
    }

    APPROVAL_REQUIRED_ACTIONS: Set[str] = {
        "change_model_registry",
        "change_security_policy",
        "change_network_policy",
        "modify_production_data",
        "upgrade_service_version",
        "quarantine_worker",
    }

    FORBIDDEN_ACTIONS: Set[str] = {
        "disable_audit_logging",
        "bypass_authorization",
        "execute_unrestricted_shell",
        "transfer_restricted_data_to_unapproved_node",
        "modify_safety_rules",
        "arbitrary_command_execution",
    }

    def __init__(self, mode: AutonomyMode = AutonomyMode.OBSERVE, initial_mode: Optional[AutonomyMode] = None):
        self.mode = initial_mode or mode
        self.allowed_automatic_actions = set(self.ALLOWED_AUTOMATIC_ACTIONS)
        self.approval_required_actions = set(self.APPROVAL_REQUIRED_ACTIONS)
        self.forbidden_actions = set(self.FORBIDDEN_ACTIONS)

    def get_mode(self) -> AutonomyMode:
        return self.mode

    def set_mode(self, mode: AutonomyMode) -> None:
        self.mode = mode

    def evaluate_action_permission(self, action: ActionPlan) -> tuple[bool, str, bool]:
        """Evaluates whether an action is permitted, forbidden, or requires human authorization.
        Returns: (is_permitted, reason, requires_human_approval)
        """
        # 1. Strictly Forbidden Gate (Hard Block)
        if action.action_type in self.forbidden_actions:
            return (
                False,
                f"Forbidden action '{action.action_type}' violates sovereign safety policy (Section 35.11).",
                False,
            )

        # 2. Requisite Human Approval Actions
        if action.action_type in self.approval_required_actions:
            return (
                True,
                f"Action '{action.action_type}' requires explicit human administrator approval before execution.",
                True,
            )

        # 3. Check Autonomy Mode Constraints
        if self.mode == AutonomyMode.OBSERVE:
            return (
                True,
                "Operating in OBSERVE mode: Action is recommended but automatic execution is disabled.",
                True,  # In observe mode, all executions require human intervention
            )

        elif self.mode == AutonomyMode.RECOMMEND_AND_APPROVE:
            return (
                True,
                "Operating in RECOMMEND_AND_APPROVE mode: Human approval required.",
                True,
            )

        elif self.mode == AutonomyMode.BOUNDED_AUTOMATION:
            if action.action_type in self.allowed_automatic_actions and action.risk_level == ActionRiskLevel.LOW:
                return (
                    True,
                    f"Action '{action.action_type}' is allowlisted and approved for autonomous execution.",
                    False,  # Can execute automatically
                )
            else:
                return (
                    True,
                    f"Action '{action.action_type}' exceeds low-risk threshold (Risk: {action.risk_level.value}). Approval required.",
                    True,
                )

        return (False, f"Unrecognized action '{action.action_type}' rejected", False)
