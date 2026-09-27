"""
Tests for Phase 25 Response Verification, Stability Monitoring, and Case Reopening.
"""

import pytest
import time
from security_operations.actions.registry import ActionRegistry, ActionRecord, ActionRiskClass, ActionState
from security_operations.verification.checks import ResponseVerificationEngine, VerificationOutcome
from security_operations.verification.monitors import RecoveryTracker, ReopenLogic
from security_operations.cases.cases import Case, CaseStatus, CasePriority


def test_telemetry_verification_success_and_failure():
    engine = ResponseVerificationEngine()
    reg = ActionRegistry()
    action = reg.register_action("CASE-01", "DISABLE_TLS10", "MTA-07", ActionRiskClass.R3_POTENTIAL_IMPACT)

    # 1. Success telemetry
    good_tel = {
        "legacy_tls_sessions_wire": 0,
        "client_error_count": 0,
        "active_cert_valid": True,
    }
    v_pass = engine.verify_action(action, observed_telemetry=good_tel)
    assert v_pass["is_verified"] is True
    assert v_pass["outcome"] == VerificationOutcome.SUCCESS.value
    assert action.state == ActionState.VERIFIED

    # 2. Failure telemetry: legacy sessions still active
    bad_tel = {
        "legacy_tls_sessions_wire": 14,
        "client_error_count": 0,
        "active_cert_valid": True,
    }
    v_fail = engine.verify_action(action, observed_telemetry=bad_tel)
    assert v_fail["is_verified"] is False
    assert v_fail["outcome"] == VerificationOutcome.FAILED.value


def test_recovery_tracking_and_reopen_logic():
    tracker = RecoveryTracker()
    case = Case(case_id="CASE-REC-01", title="Recurrence test", description="Testing", asset_id="MTA-07")
    sess = tracker.start_monitoring(case, window_duration_seconds=10)

    # Check stability immediately
    chk1 = tracker.check_stability(sess.session_id, current_time=time.time())
    assert chk1["status"] == "ACTIVE"

    # Simulate 15 seconds elapsed
    chk2 = tracker.check_stability(sess.session_id, current_time=time.time() + 15)
    assert chk2["status"] == "PASSED"

    # Mark resolved, then test recurrence reopen
    case.status = CaseStatus.RESOLVED
    reopened, msg = ReopenLogic.evaluate_recurrence(case, "tls_downgrade", "MTA-07")
    assert reopened is True
    assert case.status == CaseStatus.REOPENED
    assert case.reopened_from == "CASE-REC-01"
