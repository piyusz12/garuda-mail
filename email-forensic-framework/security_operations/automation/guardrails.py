"""
Phase 25 — Security Automation Guardrails
Hard architectural boundaries preventing runaway automated impacts on critical infrastructure.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
import time


@dataclass
class AutomationGuardrails:
    max_affected_assets: int = 5
    max_actions_per_hour: int = 20
    blocked_asset_classes: Set[str] = field(default_factory=lambda: {
        "CORE_IDENTITY_GATEWAY",
        "PRIMARY_ROOT_CA",
        "GLOBAL_MX_RELAY",
    })
    block_outside_maintenance_windows_for_high_impact: bool = True


class GuardrailEnforcer:
    """Enforces enterprise safety guardrails on automated operational executions."""

    def __init__(self, guardrails: Optional[AutomationGuardrails] = None):
        self.guardrails = guardrails or AutomationGuardrails()
        self._action_timestamps: List[float] = []

    def check_guardrails(
        self,
        target_asset: str,
        target_class: str,
        affected_count: int,
        is_high_impact: bool = False,
        in_maintenance: bool = True,
    ) -> Tuple[bool, str]:
        now = time.time()
        # Clean timestamps older than 1 hour
        self._action_timestamps = [t for t in self._action_timestamps if now - t < 3600]

        # 1. Frequency limit check
        if len(self._action_timestamps) >= self.guardrails.max_actions_per_hour:
            return False, f"Rate limit reached: {len(self._action_timestamps)} actions in the past hour."

        # 2. Scope limit check
        if affected_count > self.guardrails.max_affected_assets:
            return False, (
                f"Scope limit exceeded: {affected_count} assets requested, "
                f"maximum allowed is {self.guardrails.max_affected_assets}."
            )

        # 3. Blocked asset classes
        if target_class in self.guardrails.blocked_asset_classes:
            return False, f"Target asset class '{target_class}' is protected by hard guardrails."

        # 4. Out-of-window high-impact protection
        if is_high_impact and not in_maintenance and self.guardrails.block_outside_maintenance_windows_for_high_impact:
            return False, "High-impact autonomous action rejected outside approved maintenance windows."

        self._action_timestamps.append(now)
        return True, "All guardrails passed."
