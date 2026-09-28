"""
End-to-End Integration and API Tests for Phase 23.
"""
import pytest
from phase_23_autonomous_threat_hunting import AutonomousThreatHuntingPlatform, app, HAS_FASTAPI
from fastapi.testclient import TestClient

def test_autonomous_threat_hunting_e2e_platform():
    platform = AutonomousThreatHuntingPlatform()
    result = platform.execute_autonomous_security_loop()
    assert result["status"] == "SUCCESS"
    assert result["steps_executed"] == 11
    assert result["promoted_rule_version"] == "1.5"

    # Verify Dashboards
    dash_eng = platform.render_detection_engineering_dashboard()
    assert "DETECTION ENGINEERING" in dash_eng

    dash_hunt = platform.render_threat_hunting_dashboard()
    assert "THREAT HUNTING" in dash_hunt

    workspace = platform.render_investigation_workspace("asset", "MTA-07")
    assert "INVESTIGATION WORKSPACE" in workspace

@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
def test_fastapi_endpoints():
    client = TestClient(app)

    # 1. Detections
    res_list = client.get("/api/v1/detections")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 3

    # 2. Test Detection
    res_test = client.post("/api/v1/detections/DET-TLS-001/test")
    assert res_test.status_code == 200
    assert "precision" in res_test.json()

    # 3. Threat Hunts
    res_hunts = client.get("/api/v1/hunts")
    assert res_hunts.status_code == 200
    assert "HUNT-TMPL-01" in res_hunts.json()["templates"]

    # 4. Run Hunt
    res_run_hunt = client.post("/api/v1/hunts/HUNT-TMPL-01/run")
    assert res_run_hunt.status_code == 200
    assert "record" in res_run_hunt.json()

    # 5. Hypotheses
    res_hyp = client.post("/api/v1/hypotheses?statement=Test+Hypothesis&asset=MTA-07&ja4=JA4-TEST")
    assert res_hyp.status_code == 200
    hyp_id = res_hyp.json()["hypothesis_id"]

    res_hyp_test = client.post(f"/api/v1/hypotheses/{hyp_id}/test")
    assert res_hyp_test.status_code == 200
    assert "status" in res_hyp_test.json()

    # 6. Investigation
    res_inv = client.post("/api/v1/investigations?entity_key=asset&entity_value=MTA-07")
    assert res_inv.status_code == 200
    assert "evidence_bundle_id" in res_inv.json()

    # 7. Validation
    res_val = client.post("/api/v1/validation/detections")
    assert res_val.status_code == 200
    assert "DET-TLS-001" in res_val.json()

    # 8. Autonomous Loop
    res_loop = client.post("/api/v1/loop/execute")
    assert res_loop.status_code == 200
    assert res_loop.json()["status"] == "SUCCESS"
