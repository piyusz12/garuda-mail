"""
Just-Enough-Privilege Access (JEPA) Scoper.
Restricts privileges to the exact action-level granular permissions required for the operational task.
"""
from typing import Dict, List, Optional, Set


class JEPAScoper:
    """Enforces fine-grained least-privilege scoping across sensitive services."""

    # Role -> Set of strictly allowed granular actions
    ROLE_ACTION_SCOPES: Dict[str, Set[str]] = {
        "SOC_ANALYST": {"read", "investigate", "export_telemetry"},
        "SOC_ADMIN": {"read", "investigate", "export_telemetry", "stage_action", "approve_action"},
        "MTA_OPERATOR": {"read", "restart_relay", "check_queue"},
        "MTA_ADMIN": {"read", "restart_relay", "check_queue", "rotate_certificate", "modify_tls_policy"},
        "GUEST_OPERATOR": {"read_public"},
    }

    @classmethod
    def is_action_authorized(cls, role: str, requested_action: str) -> bool:
        allowed = cls.ROLE_ACTION_SCOPES.get(role, set())
        return requested_action in allowed

    @classmethod
    def get_scoped_actions(cls, role: str) -> List[str]:
        return sorted(list(cls.ROLE_ACTION_SCOPES.get(role, set())))
