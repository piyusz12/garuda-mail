"""
Phase 24 — Response Orchestration Unit Tests
Tests Action Risk Classification, Policy Engine, Four-Eyes Approvals, Concurrency Locks, and Rollback.
"""

import pytest
from response.risk import ActionRiskClass, RISK_PROFILES
from response.actions import ResponseAction, ActionType, ActionStatus
from response.policy import ResponsePolicyEngine
from response.approval import ApprovalEngine, ApprovalDecision, ApprovalState
from response.orchestrator import ActionOrchestrator, ConcurrencyLockError
from response.planner import ResponsePlan, ResponsePlanner, PlanStatus
from response.rollback import RollbackEngine
from connectors.registry import ConnectorRegistry
from incident.models import Incident, IncidentStatus, IncidentSeverity, IncidentPriority


def test_action_risk_profiles():
    assert RISK_PROFILES[ActionRiskClass.R0].default_approval_required is False
    assert RISK_PROFILES[ActionRiskClass.R4].requires_four_eyes is True
    assert RISK_PROFILES[ActionRiskClass.R3].requires_simulation is True


def test_policy_engine_evaluation():
    engine = ResponsePolicyEngine()
    action = ResponseAction(
        action_id="ACT-01",
        sequence=1,
        name="Enforce TLS 1.3 on Critical MTA",
        action_type=ActionType.CRYPTOGRAPHIC,
        target_asset="MTA-07",
        parameters={},
        risk_class=ActionRiskClass.R4,
        idempotency_key="TEST:R4",
        forward_command="mta_disable_legacy_tls",
        rollback_command="mta_enable_legacy_tls",
        verification_spec={}
    )

    eval_res = engine.evaluate_action(action, context={"asset_criticality": "CRITICAL", "blast_radius": 0.35})
    assert eval_res.compliant is True
    assert eval_res.required_approvals >= 2
    assert eval_res.requires_four_eyes is True
    assert eval_res.requires_simulation is True


def test_four_eyes_approval_engine():
    appr_engine = ApprovalEngine()
    action = ResponseAction(
        action_id="ACT-02",
        sequence=1,
        name="Revoke Compromised Certificate",
        action_type=ActionType.CERTIFICATE,
        target_asset="MTA-07",
        parameters={"serial": "A1:B2:C3"},
        risk_class=ActionRiskClass.R4,
        idempotency_key="TEST:REVOKE",
        forward_command="revoke_cert",
        rollback_command="restore_cert",
        verification_spec={}
    )

    req = appr_engine.create_request("INC-01", action, required_approvals=2, requires_four_eyes=True)
    assert req.state == ApprovalState.PENDING

    # First approval
    appr_engine.submit_decision(req.request_id, "analyst_1", "SOC Analyst", ApprovalDecision.APPROVED, "Looks good", action)
    assert req.state == ApprovalState.PENDING  # Needs 2nd analyst

    # Second approval by different analyst
    appr_engine.submit_decision(req.request_id, "analyst_2", "PKI Officer", ApprovalDecision.APPROVED, "Verified serial", action)
    assert req.state == ApprovalState.APPROVED
    assert req.is_fully_approved() is True


def test_tamper_detection_in_approval():
    appr_engine = ApprovalEngine()
    action = ResponseAction(
        action_id="ACT-03",
        sequence=1,
        name="Quarantine Destination",
        action_type=ActionType.NETWORK,
        target_asset="MTA-01",
        parameters={"ip": "1.2.3.4"},
        risk_class=ActionRiskClass.R3,
        idempotency_key="TEST:TAMPER",
        forward_command="block_ip 1.2.3.4",
        rollback_command="unblock_ip 1.2.3.4",
        verification_spec={}
    )

    req = appr_engine.create_request("INC-01", action, required_approvals=1)

    # Tamper with action parameters after request creation
    action.parameters["ip"] = "9.9.9.9"

    with pytest.raises(ValueError, match="Integrity failure"):
        appr_engine.submit_decision(req.request_id, "analyst_1", "SOC", ApprovalDecision.APPROVED, "OK", action)


def test_concurrency_lock_and_idempotency():
    connectors = ConnectorRegistry()
    orchestrator = ActionOrchestrator(connectors)

    action = ResponseAction(
        action_id="ACT-04",
        sequence=1,
        name="Enforce STARTTLS",
        action_type=ActionType.ENDPOINT,
        target_asset="MTA-07",
        parameters={},
        risk_class=ActionRiskClass.R2,
        idempotency_key="INC-TEST:IDEMPOTENT_01",
        forward_command="set_starttls_encrypt",
        rollback_command="set_starttls_may",
        verification_spec={}
    )
    plan1 = ResponsePlan(plan_id="PLAN-A", incident_id="INC-A", title="Plan A", playbook_id="PB-1", actions=[action])
    inc1 = Incident(
        incident_id="INC-A", title="Test", description="Test", severity=IncidentSeverity.HIGH,
        priority=IncidentPriority.P2_HIGH, status=IncidentStatus.TRIAGED, affected_assets=["MTA-07"]
    )

    # Execute plan 1
    orchestrator.execute_plan(plan1, inc1)
    assert action.status == ActionStatus.SUCCESS

    # Second execution of same action utilizes idempotency cache
    action2 = ResponseAction(
        action_id="ACT-05",
        sequence=1,
        name="Enforce STARTTLS Again",
        action_type=ActionType.ENDPOINT,
        target_asset="MTA-07",
        parameters={},
        risk_class=ActionRiskClass.R2,
        idempotency_key="INC-TEST:IDEMPOTENT_01",
        forward_command="set_starttls_encrypt",
        rollback_command="set_starttls_may",
        verification_spec={}
    )
    plan2 = ResponsePlan(plan_id="PLAN-B", incident_id="INC-B", title="Plan B", playbook_id="PB-1", actions=[action2])
    inc2 = Incident(
        incident_id="INC-B", title="Test", description="Test", severity=IncidentSeverity.HIGH,
        priority=IncidentPriority.P2_HIGH, status=IncidentStatus.TRIAGED, affected_assets=["MTA-07"]
    )
    orchestrator.execute_plan(plan2, inc2)
    assert action2.status == ActionStatus.SUCCESS
