"""
Tests for Phase 25 Action Safety, Idempotency, Concurrency Locks, Approvals, and Adapters.
"""

import pytest
from security_operations.actions.registry import ActionRegistry, ActionRecord, ActionRiskClass, ActionState
from security_operations.actions.idempotency import IdempotencyManager, ConcurrencyLockManager
from security_operations.actions.executor import ActionSafetyEngine, ActionExecutor
from security_operations.approvals.workflow import ApprovalWorkflow, ApprovalTier


def test_action_idempotency_and_locks():
    idem = IdempotencyManager()
    key = IdempotencyManager.compute_key("CASE-101", "DISABLE_TLS10", "MTA-07")
    already_run, res = idem.is_executed(key)
    assert not already_run

    idem.record_execution(key, {"status": "SUCCESS"})
    already_run2, res2 = idem.is_executed(key)
    assert already_run2 is True
    assert res2["status"] == "SUCCESS"

    locks = ConcurrencyLockManager()
    assert locks.acquire_asset_lock("MTA-07", "CASE-101") is True
    # Conflicting case cannot acquire same asset
    assert locks.acquire_asset_lock("MTA-07", "CASE-999") is False
    locks.release_asset_lock("MTA-07", "CASE-101")
    assert locks.acquire_asset_lock("MTA-07", "CASE-999") is True


def test_four_eyes_approval_workflow():
    workflow = ApprovalWorkflow()
    req = workflow.create_request(
        action_id="ACT-881",
        case_id="CASE-101",
        tier=ApprovalTier.CRITICAL,
        action_payload={"action_type": "FLEET_CRYPTO_ROTATE", "target": "ALL_MTAS"},
    )
    assert req.required_approvals == 2
    assert req.status == "PENDING"

    # First approval
    workflow.submit_decision(req.request_id, "analyst-1", "Analyst", "APPROVED", "Checks ok")
    assert req.status == "PENDING"

    # Same approver voting again rejected
    with pytest.raises(ValueError):
        workflow.submit_decision(req.request_id, "analyst-1", "Analyst", "APPROVED", "Duplicate vote")

    # Second independent approval
    workflow.submit_decision(req.request_id, "analyst-2", "Senior Lead", "APPROVED", "Four-Eyes confirmed")
    assert req.status == "APPROVED"
    assert req.is_fully_approved() is True


def test_service_adapter_execution_diff():
    executor = ActionExecutor()
    reg = ActionRegistry()
    action = reg.register_action(
        case_id="CASE-MTA",
        action_type="DISABLE_LEGACY_TLS",
        target="MTA-07",
        risk_class=ActionRiskClass.R3_POTENTIAL_IMPACT,
    )

    res = executor.execute_action(action, context={"services": ["smtp", "mta"]})
    assert res["status"] == "SUCCESS"
    assert action.state == ActionState.COMPLETED
    assert action.snapshot_before["tls_min_version"] == "TLSv1.0"
    assert action.snapshot_after["tls_min_version"] == "TLSv1.2"
