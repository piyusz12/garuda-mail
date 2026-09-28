"""
End-to-End Integration and REST API Test Suite for Phase 25 Autonomous Security Operations & SOAR.
"""

import pytest
from fastapi.testclient import TestClient
from phase_25_autonomous_security_operations import app, orchestrator
from security_operations.cases.cases import CaseStatus
from security_operations.actions.registry import ActionState


@pytest.fixture
def client():
    return TestClient(app)


def test_phase25_full_orchestration_lifecycle():
    # 1. Ingest alert
    alert_payload = {
        "source": "cert_analyzer",
        "severity": "CRITICAL",
        "asset_id": "MTA-07",
        "event_type": "certificate_change",
        "certificate_id": "CERT-UNKNOWN-UNTRUSTED",
        "details": {"issue": "Untrusted self-signed certificate"},
    }
    ingest_res = orchestrator.process_alert(alert_payload)
    case_id = ingest_res["case_id"]
    assert case_id is not None

    # 2. Automated Investigation
    inv_res = orchestrator.investigate_case(case_id)
    assert inv_res["risk_score"] > 50
    assert inv_res["decision"] in ("REQUEST_APPROVAL", "ESCALATE", "EXECUTE_AUTOMATICALLY")

    # 3. Stage Action
    action = orchestrator.stage_response_action(
        case_id=case_id,
        action_type="ROTATE_CERTIFICATE",
        target="MTA-07",
        parameters={"new_cert_id": "CERT-2026-PRIMARY"},
    )
    assert action.action_id is not None

    # 4. Human Approval
    reqs = [r for r in orchestrator.approval_workflow.list_requests() if r.action_id == action.action_id]
    assert len(reqs) > 0
    app_req = reqs[0]
    orchestrator.approval_workflow.submit_decision(
        request_id=app_req.request_id,
        approver_id="analyst-lead",
        role="Security Lead",
        decision="APPROVED",
        reason="Approved cert replacement",
    )

    # 5. Execute Action
    exec_res = orchestrator.execute_approved_action(action.action_id)
    assert exec_res["status"] == "SUCCESS"
    assert action.state == ActionState.COMPLETED

    # 6. Verification
    v_res = orchestrator.verify_action(action.action_id, telemetry={
        "legacy_tls_sessions_wire": 0,
        "client_error_count": 0,
        "active_cert_valid": True,
    })
    assert v_res["is_verified"] is True

    # 7. Close Case with PIR & Evidence Package
    close_res = orchestrator.close_case_with_report(case_id)
    assert close_res["status"] == CaseStatus.CLOSED.value
    assert "report" in close_res
    assert "package_hash" in close_res["evidence_package"]


def test_fastapi_rest_endpoints(client):
    # 1. Ingest alert
    resp = client.post("/api/v1/alerts", json={
        "source": "tls_analyzer",
        "severity": "HIGH",
        "asset_id": "MTA-02",
        "event_type": "tls_downgrade",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "cluster_id" in data

    # 2. Create fresh case
    create_resp = client.post("/api/v1/cases", json={
        "title": "API Test Case",
        "description": "API verification",
        "asset_id": "MTA-02",
        "priority": "HIGH",
    })
    assert create_resp.status_code == 200
    test_case_id = create_resp.json()["case_id"]

    # 3. Investigate
    inv_resp = client.post(f"/api/v1/cases/{test_case_id}/investigate")
    assert inv_resp.status_code == 200
    assert "risk_score" in inv_resp.json()

    # 4. Graph endpoint
    graph_resp = client.get(f"/api/v1/cases/{test_case_id}/graph")
    assert graph_resp.status_code == 200
    assert "nodes" in graph_resp.json()

    # 5. SOC Dashboard
    soc_resp = client.get("/api/v1/soc/dashboard")
    assert soc_resp.status_code == 200
    soc_data = soc_resp.json()
    assert "open_cases" in soc_data
    assert "actions_executed" in soc_data
