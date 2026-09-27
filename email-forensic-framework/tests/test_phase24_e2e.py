"""
Phase 24 — End-to-End Autonomous Incident Response & SOAR Integration Tests
Tests full lifecycle execution from Phase 23 findings to Phase 24 remediation, verification, reports, and REST endpoints.
"""

import pytest
from phase_24_autonomous_incident_response import AutonomousIncidentResponsePlatform, HAS_FASTAPI
from incident.models import IncidentSeverity, IncidentStatus

if HAS_FASTAPI:
    from fastapi.testclient import TestClient
    from phase_24_autonomous_incident_response import app


def test_phase24_end_to_end_lifecycle():
    platform = AutonomousIncidentResponsePlatform()
    res = platform.qualify_and_respond(
        title="STARTTLS Stripping Attack on Inbound MX",
        description="Passive sensors detected cleartext AUTH after stripped STARTTLS",
        severity=IncidentSeverity.CRITICAL,
        affected_assets=["MTA-04", "MTA-01"],
        detection_rule="DET-AUTH-003"
    )

    # 1. Incident creation & triage
    inc = res["incident"]
    assert inc["incident_id"].startswith("INC-")
    assert inc["status"] == "MONITORING"
    assert inc["priority"] == "P1_CRITICAL"

    # 2. Response Plan
    plan = res["plan"]
    assert len(plan["actions"]) >= 5
    assert plan["status"] == "COMPLETED"

    # 3. Blast radius & Simulation
    assert res["blast_radius"]["blast_radius_ratio"] > 0.0
    assert res["simulation"]["safe_to_proceed"] is True

    # 4. Approvals
    assert res["approval"]["state"] == "APPROVED"
    assert len(res["approval"]["signatures"]) == 2

    # 5. Verification
    assert res["verification"]["verdict"] == "PASS"

    # 6. Watcher
    assert res["watcher"]["status"] == "ACTIVE"

    # 7. Post-Incident Report & Lessons Learned
    assert res["report"]["incident_id"] == inc["incident_id"]
    assert res["lessons"]["incident_id"] == inc["incident_id"]
    assert len(res["lessons"]["response_strengths"]) >= 1


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
def test_phase24_fastapi_rest_endpoints():
    client = TestClient(app)

    # 1. List Incidents
    r = client.get("/api/v1/incidents")
    assert r.status_code == 200
    assert isinstance(r.json(), list)

    # 2. Create Incident via API
    r = client.post("/api/v1/incidents?title=REST+API+Incident&severity=HIGH", json=["MTA-07"])
    assert r.status_code == 200
    inc_data = r.json()
    inc_id = inc_data["incident_id"]
    assert inc_id.startswith("INC-")

    # 3. Get Incident
    r = client.get(f"/api/v1/incidents/{inc_id}")
    assert r.status_code == 200
    assert r.json()["incident_id"] == inc_id

    # 4. Generate Response Plan via API
    r = client.post(f"/api/v1/incidents/{inc_id}/plans")
    assert r.status_code == 200
    plan_data = r.json()
    plan_id = plan_data["plan_id"]
    assert plan_id.startswith("PLAN-")

    # 5. Simulate Plan via API
    r = client.post(f"/api/v1/plans/{plan_id}/simulate")
    assert r.status_code == 200
    assert "compatibility_score" in r.json()

    # 6. Execute Plan via API
    r = client.post(f"/api/v1/plans/{plan_id}/execute")
    assert r.status_code == 200
    assert r.json()["status"] == "COMPLETED"

    # 7. Get Post-Incident Report via API
    r = client.get(f"/api/v1/incidents/{inc_id}/report")
    assert r.status_code == 200
    assert r.json()["incident_id"] == inc_id
