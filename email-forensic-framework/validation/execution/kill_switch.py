"""
Kill Switch & Automatic Stop Controller.
Provides emergency abort across global, campaign, scenario, and target boundaries.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any
from enum import Enum
import time


class KillSwitchScope(str, Enum):
    GLOBAL = "GLOBAL"
    CAMPAIGN = "CAMPAIGN"
    SCENARIO = "SCENARIO"
    TARGET = "TARGET"


@dataclass
class KillSwitchEvent:
    event_id: str
    scope: KillSwitchScope
    target_identifier: str  # 'ALL', campaign_id, run_id, or asset_id
    triggered_by: str
    reason: str
    timestamp: float = field(default_factory=time.time)
    rollback_executed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "scope": self.scope.value if isinstance(self.scope, KillSwitchScope) else self.scope,
            "target_identifier": self.target_identifier,
            "triggered_by": self.triggered_by,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "rollback_executed": self.rollback_executed,
        }


class KillSwitchManager:
    """Manages manual emergency stops and automatic safety triggers."""

    def __init__(self):
        self._global_halt: bool = False
        self._halted_campaigns: Set[str] = set()
        self._halted_scenarios: Set[str] = set()
        self._halted_targets: Set[str] = set()
        self._history: List[KillSwitchEvent] = []
        self._rollback_hooks: List[Callable[[], None]] = []

    def register_rollback_hook(self, hook: Callable[[], None]) -> None:
        self._rollback_hooks.append(hook)

    def trigger_global_stop(self, operator_id: str, reason: str = "Operator manual emergency stop") -> KillSwitchEvent:
        """Immediately halts all emulation activity across all cyber ranges."""
        self._global_halt = True
        evt = KillSwitchEvent(
            event_id=f"KS-GLOB-{int(time.time() * 1000)}",
            scope=KillSwitchScope.GLOBAL,
            target_identifier="ALL",
            triggered_by=operator_id,
            reason=reason,
        )
        self._history.append(evt)
        self._execute_rollbacks()
        return evt

    def trigger_campaign_stop(self, campaign_id: str, operator_id: str, reason: str) -> KillSwitchEvent:
        self._halted_campaigns.add(campaign_id)
        evt = KillSwitchEvent(
            event_id=f"KS-CAMP-{int(time.time() * 1000)}",
            scope=KillSwitchScope.CAMPAIGN,
            target_identifier=campaign_id,
            triggered_by=operator_id,
            reason=reason,
        )
        self._history.append(evt)
        self._execute_rollbacks()
        return evt

    def trigger_scenario_stop(self, run_id: str, operator_id: str, reason: str) -> KillSwitchEvent:
        self._halted_scenarios.add(run_id)
        evt = KillSwitchEvent(
            event_id=f"KS-SCN-{int(time.time() * 1000)}",
            scope=KillSwitchScope.SCENARIO,
            target_identifier=run_id,
            triggered_by=operator_id,
            reason=reason,
        )
        self._history.append(evt)
        self._execute_rollbacks()
        return evt

    def trigger_target_stop(self, asset_id: str, operator_id: str, reason: str) -> KillSwitchEvent:
        self._halted_targets.add(asset_id)
        evt = KillSwitchEvent(
            event_id=f"KS-TGT-{int(time.time() * 1000)}",
            scope=KillSwitchScope.TARGET,
            target_identifier=asset_id,
            triggered_by=operator_id,
            reason=reason,
        )
        self._history.append(evt)
        self._execute_rollbacks()
        return evt

    def is_halted(self, campaign_id: Optional[str] = None, run_id: Optional[str] = None, asset_id: Optional[str] = None) -> bool:
        if self._global_halt:
            return True
        if campaign_id and campaign_id in self._halted_campaigns:
            return True
        if run_id and run_id in self._halted_scenarios:
            return True
        if asset_id and asset_id in self._halted_targets:
            return True
        return False

    def reset_global_stop(self) -> None:
        self._global_halt = False

    def _execute_rollbacks(self) -> None:
        for hook in self._rollback_hooks:
            try:
                hook()
            except Exception:
                pass

    def list_events(self) -> List[KillSwitchEvent]:
        return list(self._history)
