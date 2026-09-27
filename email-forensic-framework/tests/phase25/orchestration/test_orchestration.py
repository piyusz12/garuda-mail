"""
Tests for Phase 25 Orchestration, Case State Machine, SLA Tracking, and Investigation DAG.
"""

import pytest
import time
from security_operations.cases.cases import Case, CaseStatus, CasePriority, CaseManager
from security_operations.cases.timeline import CaseTimeline
from security_operations.orchestrator.states import CaseStateMachine
from security_operations.orchestrator.scheduler import SLATracker, EscalationEngine
from security_operations.investigation.dag import InvestigationDAG
from security_operations.investigation.context import MaintenanceWindowChecker


def test_case_state_machine_valid_and_invalid_transitions():
    case = Case(
        case_id="CASE-TEST-01",
        title="TLS Downgrade Investigation",
        description="Testing state transitions",
    )
    assert case.status == CaseStatus.NEW

    # Valid: NEW -> TRIAGED
    CaseStateMachine.transition(case, CaseStatus.TRIAGED)
    assert case.status == CaseStatus.TRIAGED

    # Valid: TRIAGED -> INVESTIGATING
    CaseStateMachine.transition(case, CaseStatus.INVESTIGATING)
    assert case.status == CaseStatus.INVESTIGATING

    # Invalid: INVESTIGATING cannot jump directly to CLOSED
    with pytest.raises(ValueError):
        CaseStateMachine.transition(case, CaseStatus.CLOSED)


def test_hash_chained_timeline_integrity():
    timeline = CaseTimeline("CASE-AUDIT-01")
    timeline.add_event(stage="STAGE_1", description="Initial alert triggered")
    timeline.add_event(stage="STAGE_2", description="Analyst reviewed")
    timeline.add_event(stage="STAGE_3", description="Action completed")

    assert len(timeline.get_events()) == 3
    assert timeline.verify_integrity() is True

    # Tamper with an event to test verification failure
    timeline.events[1]["description"] = "TAMPERED DATA"
    assert timeline.verify_integrity() is False


def test_investigation_dag_execution():
    dag = InvestigationDAG()
    order = dag.get_execution_order()
    task_names = [t.name for t in order]

    # Verify ResolveAsset runs before dependent tasks
    assert "ResolveAsset" in task_names
    assert task_names.index("ResolveAsset") < task_names.index("GetCertificateHistory")

    ctx = dag.execute({"asset_id": "MTA-07", "timestamp": time.time()})
    assert ctx["asset_id"] == "MTA-07"
    assert "criticality" in ctx
    assert "certificate_history" in ctx
    assert "has_historical_recurrence" in ctx
    assert ctx["has_historical_recurrence"] is True


def test_sla_tracker_and_escalation():
    case = Case(
        case_id="CASE-SLA-01",
        title="Critical MTA Outage",
        description="Immediate response required",
        priority=CasePriority.CRITICAL,
        created_at=time.time() - 700,  # 700 seconds elapsed (over 10m)
    )

    sla_res = SLATracker.check_sla(case)
    assert sla_res["triage_breached"] is True
    assert sla_res["is_sla_breached"] is True

    escalated, msg = EscalationEngine.evaluate_escalation(case)
    assert escalated is True
    assert case.status == CaseStatus.ESCALATED
