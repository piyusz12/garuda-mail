"""Scenario Execution, Safety, Kill Switch, and Scope."""
from .scope import ScopeValidator, ScopeViolationError
from .safety import SafetyController, SafetyCheckResult, SafetyStatus
from .kill_switch import KillSwitchManager, KillSwitchEvent, KillSwitchScope
from .runner import ScenarioRunner, ValidationRun, ValidationStepRecord, ScenarioOutcome

__all__ = [
    "ScopeValidator",
    "ScopeViolationError",
    "SafetyController",
    "SafetyCheckResult",
    "SafetyStatus",
    "KillSwitchManager",
    "KillSwitchEvent",
    "KillSwitchScope",
    "ScenarioRunner",
    "ValidationRun",
    "ValidationStepRecord",
    "ScenarioOutcome",
]
