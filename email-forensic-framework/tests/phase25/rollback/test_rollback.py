"""
Tests for Phase 25 Automated Rollback on Remediation Failure.
"""

import pytest
from security_operations.actions.registry import ActionRegistry, ActionRiskClass, ActionState
from security_operations.actions.executor import ActionExecutor
from security_operations.verification.rollback import RollbackEngine


def test_service_configuration_rollback():
    executor = ActionExecutor()
    rollback_engine = RollbackEngine(executor)
    reg = ActionRegistry()

    action = reg.register_action(
        case_id="CASE-RB-01",
        action_type="DISABLE_LEGACY_TLS",
        target="MTA-07",
        risk_class=ActionRiskClass.R3_POTENTIAL_IMPACT,
    )

    # 1. Execute action
    executor.execute_action(action)
    assert executor.adapters["service"].configs["MTA-07"]["tls_min_version"] == "TLSv1.2"

    # 2. Trigger rollback
    rb_res = rollback_engine.execute_rollback(action, reason="Verification failed")
    assert rb_res["status"] == "ROLLED_BACK"
    assert action.state == ActionState.ROLLED_BACK
    # Configuration should be restored to before snapshot (TLSv1.0)
    assert executor.adapters["service"].configs["MTA-07"]["tls_min_version"] == "TLSv1.0"
