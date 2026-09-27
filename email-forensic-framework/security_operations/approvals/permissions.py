"""
Phase 25 — Agent Tool Permissions & Action Sandbox
Restricts copilot/AI agent abilities into governed stages: OBSERVE -> RECOMMEND -> SIMULATE -> APPROVED_EXECUTE.
"""

from enum import Enum
from typing import Set, Dict, Any, Optional


class AgentPermission(str, Enum):
    READ_TELEMETRY = "READ_TELEMETRY"
    READ_CASES = "READ_CASES"
    READ_GRAPH = "READ_GRAPH"
    READ_INTELLIGENCE = "READ_INTELLIGENCE"
    CREATE_CASE = "CREATE_CASE"
    RECOMMEND_ACTION = "RECOMMEND_ACTION"
    REQUEST_APPROVAL = "REQUEST_APPROVAL"
    EXECUTE_LOW_RISK_ACTION = "EXECUTE_LOW_RISK_ACTION"
    EXECUTE_HIGH_RISK_ACTION = "EXECUTE_HIGH_RISK_ACTION"
    ROLLBACK_ACTION = "ROLLBACK_ACTION"
    OVERRIDE_AUTOMATION = "OVERRIDE_AUTOMATION"


class AgentActionSandbox:
    """Enforces sandbox constraints on autonomous agents and copilots."""

    DEFAULT_COPILOT_PERMISSIONS: Set[AgentPermission] = {
        AgentPermission.READ_TELEMETRY,
        AgentPermission.READ_CASES,
        AgentPermission.READ_GRAPH,
        AgentPermission.READ_INTELLIGENCE,
        AgentPermission.CREATE_CASE,
        AgentPermission.RECOMMEND_ACTION,
        AgentPermission.REQUEST_APPROVAL,
    }

    def __init__(self, granted_permissions: Optional[Set[AgentPermission]] = None):
        self.permissions = granted_permissions or set(self.DEFAULT_COPILOT_PERMISSIONS)

    def has_permission(self, permission: AgentPermission) -> bool:
        return permission in self.permissions

    def validate_action(self, permission: AgentPermission, target_asset: str = "") -> bool:
        """Checks if the agent is authorized to invoke this operational action."""
        if not self.has_permission(permission):
            raise PermissionError(
                f"Agent lacks permission '{permission.value}'. Autonomous bypass blocked by safety sandbox."
            )
        return True
