"""
Phase 25 — Decision Policies & Governance Rules
Configures policy thresholds and autonomy gates mapping risk/context to operational actions.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class DecisionPolicy:
    policy_id: str
    tenant_id: str = "default"
    autonomy_level: int = 2  # 0=observe, 1=recommend, 2=prepare, 3=low-impact execute, 4=autonomous
    monitor_threshold: float = 20.0
    investigate_threshold: float = 40.0
    escalate_threshold: float = 70.0
    response_threshold: float = 80.0
    require_approval_for_critical_assets: bool = True
    blocked_actions: List[str] = field(default_factory=lambda: ["HARD_ISOLATE_CORE_GATEWAY"])


class PolicyRegistry:
    """Manages tenant-specific and global decision policies."""

    def __init__(self):
        self._policies: Dict[str, DecisionPolicy] = {
            "default": DecisionPolicy(policy_id="POL-DEFAULT", tenant_id="default", autonomy_level=2),
            "tenant_autonomous": DecisionPolicy(policy_id="POL-AUTO", tenant_id="tenant_auto", autonomy_level=4),
            "tenant_restricted": DecisionPolicy(policy_id="POL-RESTRICTED", tenant_id="tenant_restricted", autonomy_level=0),
        }

    def get_policy(self, tenant_id: str = "default") -> DecisionPolicy:
        return self._policies.get(tenant_id, self._policies["default"])

    def set_policy(self, policy: DecisionPolicy):
        self._policies[policy.tenant_id] = policy
