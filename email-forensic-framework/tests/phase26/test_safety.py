"""Tests for Safety Controller, Blast Radius, Scope Validation, and Kill Switch."""
import pytest
from validation.scenarios import ScenarioRepository, ScenarioBuilder
from validation.range import RangeManager
from validation.execution import (
    SafetyController,
    SafetyStatus,
    KillSwitchManager,
    KillSwitchScope,
    ScopeValidator,
    ScopeViolationError,
)


def test_safety_controller_prechecks():
    range_mgr = RangeManager()
    range_a = range_mgr.get_range("RANGE-A")
    repo = ScenarioRepository()
    scn_cert = repo.get("SCN-102")

    safety = SafetyController()
    res = safety.evaluate(scn_cert, range_a, operator_role="Scenario Operator")
    assert res.status == SafetyStatus.APPROVED
    assert res.is_safe_to_run is True
    assert "TARGET_CHECK" in res.passed_checks
    assert "SCOPE_CHECK" in res.passed_checks


def test_safety_controller_blocks_invalid_targets():
    range_mgr = RangeManager()
    range_a = range_mgr.get_range("RANGE-A")

    # Scenario targeting nonexistent or blocked asset
    unsafe_scn = (
        ScenarioBuilder("SCN-UNSAFE")
        .with_targets(["PROD-GATEWAY-01"])
        .build()
    )

    safety = SafetyController()
    res = safety.evaluate(unsafe_scn, range_a)
    assert res.status == SafetyStatus.BLOCKED
    assert res.is_safe_to_run is False
    assert any("TARGET_CHECK" in f or "SCOPE_CHECK" in f for f in res.failed_checks)


def test_kill_switch_lifecycle():
    ks = KillSwitchManager()
    rollback_called = []
    ks.register_rollback_hook(lambda: rollback_called.append(True))

    assert ks.is_halted(run_id="RUN-123") is False

    # Scenario-level stop
    ks.trigger_scenario_stop("RUN-123", operator_id="analyst-lead", reason="Test halt")
    assert ks.is_halted(run_id="RUN-123") is True
    assert ks.is_halted(run_id="RUN-999") is False
    assert len(rollback_called) == 1

    # Global stop
    ks.trigger_global_stop(operator_id="ciso", reason="Global emergency stop")
    assert ks.is_halted(run_id="RUN-999") is True
    assert len(rollback_called) == 2

    # Reset
    ks.reset_global_stop()
    assert ks.is_halted(run_id="RUN-999") is False
