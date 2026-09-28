"""
End-to-End Integration and REST API Test Suite for Phase 26:
Continuous Adversary Emulation, Purple Team, Cyber Range & Security Validation.
"""
import pytest
from fastapi.testclient import TestClient

from phase_26_continuous_security_validation import (
    app,
    runner,
    scenario_repo,
    gap_manager,
    remediation_retester,
    purple_team_engine,
    campaign_engine,
)
from validation.scenarios import ScenarioRepository
from validation.execution import ScenarioOutcome
from validation.gaps import GapStatus, GapType, GapSeverity
from validation.copilot import ValidationCopilot


@pytest.fixture
def client():
    return TestClient(app)


def test_phase26_full_end_to_end_validation_loop():
    # 1. Select Scenario SCN-102 (Certificate Regression Validation)
    scn = scenario_repo.get("SCN-102")
    assert scn is not None
    assert scn.target_assets == ["MTA-07"]

    # 2. Run Scenario in Cyber Range A
    run_record = runner.run(
        scenario=scn,
        range_id="RANGE-A",
        operator_role="Scenario Operator",
    )
    assert run_record.outcome in (ScenarioOutcome.PASS, ScenarioOutcome.PARTIAL_PASS)
    assert run_record.run_id.startswith("RUN-")
    assert run_record.duration_seconds > 0
    assert len(run_record.telemetry_observed) > 0
    assert "certificate_event" in run_record.telemetry_observed
    assert "CERT-CHANGE-001" in run_record.detections_fired

    # Check latencies recorded
    assert run_record.ttv_seconds is not None
    assert run_record.ttd_seconds is not None
    assert len(run_record.timeline) >= 4

    # 3. Simulate a Detection Gap and ensure gap management lifecycle operates correctly
    gap_run = runner.run(
        scenario=scn,
        range_id="RANGE-A",
        simulate_detection_gap=True,
    )
    assert gap_run.outcome == ScenarioOutcome.DETECTION_GAP
    assert len(gap_run.gaps_identified) > 0

    # Create tracked Validation Gap
    gap = gap_manager.create_gap(
        gap_type=GapType.DETECTION_GAP,
        technique_id="TECH-CERT-001",
        target_asset="MTA-07",
        scenario_id=scn.scenario_id,
        run_id=gap_run.run_id,
        severity=GapSeverity.HIGH,
        title="Detector CERT-CHANGE-001 failed during adversary emulation",
        description="Controlled cert change event did not fire alert",
    )
    assert gap.status == GapStatus.NEW
    assert gap.owner_team == "detection_engineering"

    # Assign & mark ready for retest
    gap_manager.assign_gap(gap.gap_id, "detection_engineering", "engineer-alice")
    assert gap.status == GapStatus.ASSIGNED

    gap_manager.mark_ready_for_retest(gap.gap_id, "Updated detection rule threshold")
    assert gap.status == GapStatus.READY_FOR_RETEST

    # 4. Retest gap and verify closure
    retest_result = remediation_retester.retest_gap(gap.gap_id, scn, range_id="RANGE-A")
    assert retest_result["retest_status"] == "PASSED"
    assert retest_result["gap_status"] == GapStatus.CLOSED.value

    # 5. Diagnostic Copilot analysis of the gap run
    diag = ValidationCopilot.diagnose_failure(gap_run)
    assert diag.root_cause_layer == "DETECTION"
    assert "Detection Failure" in diag.summary


def test_phase26_fastapi_rest_endpoints(client):
    # 1. Create a new validation scenario
    create_resp = client.post("/api/v1/validation/scenarios", json={
        "scenario_id": "SCN-API-99",
        "name": "API Test Adversary Scenario",
        "description": "Validates API endpoint execution",
        "target_assets": ["MTA-07"],
        "technique_ids": ["TECH-042"],
        "expected_telemetry": ["tls_event"],
        "expected_detections": ["TLS-LEGACY-001"],
        "expected_response_action": "ISOLATE_HOST",
        "blast_radius": "LOW",
    })
    assert create_resp.status_code == 200
    assert create_resp.json()["status"] == "CREATED"

    # 2. Get scenario
    get_resp = client.get("/api/v1/validation/scenarios/SCN-API-99")
    assert get_resp.status_code == 200
    assert get_resp.json()["scenario_id"] == "SCN-API-99"

    # 3. Simulate scenario
    sim_resp = client.post("/api/v1/validation/scenarios/SCN-API-99/simulate")
    assert sim_resp.status_code == 200
    assert sim_resp.json()["is_safe_to_run"] is True

    # 4. Approve scenario
    appr_resp = client.post("/api/v1/validation/scenarios/SCN-API-99/approve", json={
        "approver_id": "lead-approver",
        "decision": "APPROVED",
        "reason": "Range isolation verified",
    })
    assert appr_resp.status_code == 200

    # 5. Execute scenario
    exec_resp = client.post("/api/v1/validation/scenarios/SCN-API-99/execute", json={
        "range_id": "RANGE-A",
        "operator_role": "Scenario Operator",
    })
    assert exec_resp.status_code == 200
    run_data = exec_resp.json()["run"]
    run_id = run_data["run_id"]
    assert run_id.startswith("RUN-")

    # 6. Check run details & timeline
    run_resp = client.get(f"/api/v1/validation/runs/{run_id}")
    assert run_resp.status_code == 200

    timeline_resp = client.get(f"/api/v1/validation/runs/{run_id}/timeline")
    assert timeline_resp.status_code == 200
    assert len(timeline_resp.json()["timeline"]) > 0

    # 7. Check coverage endpoint
    cov_resp = client.get("/api/v1/validation/coverage")
    assert cov_resp.status_code == 200
    assert "visibility_coverage_pct" in cov_resp.json()

    # 8. Run Campaign
    camp_resp = client.post("/api/v1/validation/campaigns/CAMP-TLS-01/run")
    assert camp_resp.status_code == 200
    camp_data = camp_resp.json()
    assert camp_data["status"] == "COMPLETED"
    report_id = camp_data["signed_report_id"]

    # 9. Get signed audit report
    rep_resp = client.get(f"/api/v1/validation/reports/{report_id}")
    assert rep_resp.status_code == 200
    rep_data = rep_resp.json()
    assert "digital_signature" in rep_data["hashes"]

    # 10. Check Scorecard
    card_resp = client.get("/api/v1/validation/scorecard")
    assert card_resp.status_code == 200
    card_data = card_resp.json()
    assert "visibility_pct" in card_data
    assert "detection_pct" in card_data
    assert "response_pct" in card_data

    # 11. Copilot diagnosis
    diag_resp = client.post("/api/v1/validation/copilot/diagnose", json={"run_id": run_id})
    assert diag_resp.status_code == 200
    assert "root_cause_layer" in diag_resp.json()
