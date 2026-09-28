"""
End-to-End Integration and REST API Verification for Phase 27.
Tests complete Section 27.106 multi-step scenario, simulation, blast radius, copilot, and FastAPI endpoints.
"""

import time
import pytest
from fastapi.testclient import TestClient

from phase_27_zero_trust_identity_control import app, pdp, session_monitor
from identity.ingestion import (
    UserIdentityRepository,
    DeviceIdentityRepository,
    ServiceIdentityRepository,
    ResourceClassification,
)
from identity.posture import DevicePostureEvaluator
from zero_trust.policy.parser import (
    ZeroTrustPolicy,
    PolicyEffect,
    PolicyCondition,
)
from zero_trust.decision.context import AccessRequestContext
from zero_trust.decision.engine import PolicyDecisionPoint
from zero_trust.simulation.access import AccessSimulator
from zero_trust.simulation.blast_radius import PolicyBlastRadiusAnalyzer
from zero_trust.simulation.policy import PolicyRegressionTester
from zero_trust.sessions.monitor import ActiveSession, SessionStatus, SessionMonitor
from zero_trust.sessions.reevaluate import (
    ContinuousAccessEvaluator,
    ReevaluationEvent,
)
from zero_trust.copilot.identity import IdentityCopilot


client = TestClient(app)


class TestSimulationAndBlastRadius:
    def test_access_simulation_what_if(self):
        p_point = PolicyDecisionPoint()
        simulator = AccessSimulator(pdp=p_point)
        ctx = AccessRequestContext(
            subject_id="ID-1192",
            subject_group="security-ops",
            subject_role="SOC_ADMIN",
            device_id="DEVICE-44",
            device_managed=True,
            device_posture="HEALTHY",
            resource_id="FORENSIC-API",
            resource_classification="CRITICAL",
            action="read",
        )
        sim_res = simulator.simulate_perturbation(
            base_context=ctx,
            attribute_overrides={"device_managed": False, "device_posture": "NONCOMPLIANT"},
            scenario_description="Hypothetical device unmanaged state",
        )
        assert sim_res.original_decision == "ALLOW"
        assert sim_res.simulated_decision == "DENY"
        assert sim_res.decision_changed is True
        assert sim_res.impact_level == "BLOCKED"

    def test_policy_blast_radius(self):
        u_repo = UserIdentityRepository()
        d_repo = DeviceIdentityRepository()
        s_repo = ServiceIdentityRepository()
        analyzer = PolicyBlastRadiusAnalyzer(u_repo, d_repo, s_repo)

        test_policy = ZeroTrustPolicy(
            policy_id="POL-RESTRICT-ALL",
            name="Universal Critical Restrict",
            effect=PolicyEffect.DENY,
            target_services=["*"],
            target_actions=["*"],
            conditions=[PolicyCondition("device.managed", "==", False)],
        )
        assessment = analyzer.evaluate_blast_radius(test_policy)
        assert assessment.affected_services_count == len(s_repo.list_all())
        assert assessment.risk_classification in ("HIGH", "CRITICAL")

    def test_policy_regression_tester(self):
        base_policies = [
            ZeroTrustPolicy(
                policy_id="POL-MTA",
                name="Allow MTA",
                effect=PolicyEffect.ALLOW,
                target_services=["MTA-07"],
                conditions=[PolicyCondition("device.managed", "==", True)],
            ),
        ]
        # Candidate accidentally adds impossible condition
        candidate_policies = [
            ZeroTrustPolicy(
                policy_id="POL-MTA",
                name="Allow MTA",
                effect=PolicyEffect.ALLOW,
                target_services=["MTA-07"],
                conditions=[
                    PolicyCondition("device.managed", "==", True),
                    PolicyCondition("session.risk", "==", "IMPOSSIBLE_RISK"),
                ],
            ),
        ]
        test_requests = [
            AccessRequestContext(
                subject_id="ID-1192",
                subject_group="security-ops",
                subject_role="SOC_ADMIN",
                device_id="DEVICE-44",
                device_managed=True,
                device_posture="HEALTHY",
                resource_id="MTA-07",
                resource_classification="CRITICAL",
                action="read",
                session_risk="LOW",
            ),
        ]
        report = PolicyRegressionTester.test_policy_change(
            baseline_policies=base_policies,
            candidate_policies=candidate_policies,
            test_requests=test_requests,
        )
        assert report.total_requests_tested == 1
        assert report.newly_denied_count == 1
        assert report.is_regression_free is False


class TestIdentityCopilot:
    def test_copilot_explanations_and_who_can_access(self):
        p_point = PolicyDecisionPoint()
        s_monitor = SessionMonitor()
        u_repo = UserIdentityRepository()
        s_repo = ServiceIdentityRepository()

        sess = ActiveSession(
            session_id="S-COPILOT-01",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
        )
        s_monitor.register_session(sess)

        copilot = IdentityCopilot(
            pdp=p_point,
            session_monitor=s_monitor,
            user_repo=u_repo,
            service_repo=s_repo,
        )

        # 1. explain_session_decision
        exp = copilot.explain_session_decision("S-COPILOT-01")
        assert exp["session_id"] == "S-COPILOT-01"
        assert exp["identity_id"] == "ID-1192"

        # 2. who_can_access
        who = copilot.who_can_access("MTA-07")
        assert who["service_id"] == "MTA-07"
        assert who["allowed_identities_count"] >= 1

        # 3. why_can_they_access
        why_can = copilot.why_can_they_access("ID-1192", "MTA-07")
        assert why_can["identity_id"] == "ID-1192"
        assert "explanation" in why_can

        # 4. why_cant_they_access
        why_cant = copilot.why_cant_they_access("ID-1192", "FORENSIC-API", "DEVICE-UNMANAGED")
        assert why_cant["decision"] == "DENY"
        assert len(why_cant["blocking_factors"]) >= 1


class TestEndToEndScenarioSection27106:
    """
    Section 27.106 End-to-End Example:
    USER-1192 -> DEVICE-44 -> MTA-07
    Normal: ALLOW
    Step 1: Device posture degrades -> MEDIUM
    Step 2: Session risk elevates -> HIGH
    Step 3: Continuous evaluation triggers -> STEP-UP
    Step 4: Step-up failure -> Session REVOKED
    """
    def test_continuous_trust_degradation_loop(self):
        monitor = SessionMonitor()
        pdp_engine = PolicyDecisionPoint()
        evaluator = ContinuousAccessEvaluator(monitor=monitor, pdp=pdp_engine)

        # Initial normal session
        sess = ActiveSession(
            session_id="S-E2E-LOOP",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="FORENSIC-API",
            status=SessionStatus.ACTIVE,
        )
        monitor.register_session(sess)
        assert sess.status == SessionStatus.ACTIVE

        # Step 1 & 2: Risk elevates on critical resource
        res_stepup = evaluator.trigger_reevaluation(
            session_id="S-E2E-LOOP",
            event=ReevaluationEvent.SESSION_ANOMALY,
            updated_signals={
                "device_managed": True,
                "device_posture": "DEGRADED",
                "session_risk": "HIGH",
                "resource_classification": "CRITICAL",
            },
        )
        assert res_stepup.action_taken == "STEP_UP"
        assert sess.status == SessionStatus.STEP_UP_PENDING

        # Step 4: Step-up fails, device posture worsens to unmanaged
        res_revoke = evaluator.trigger_reevaluation(
            session_id="S-E2E-LOOP",
            event=ReevaluationEvent.POSTURE_CHANGED,
            updated_signals={
                "device_managed": False,
                "device_posture": "NONCOMPLIANT",
                "resource_classification": "CRITICAL",
            },
        )
        assert res_revoke.action_taken == "REVOKE"
        assert sess.status == SessionStatus.REVOKED


class TestFastAPIRoutes:
    def test_identity_lookup_and_history(self):
        r_get = client.get("/api/v1/identities/ID-1192")
        assert r_get.status_code == 200
        data = r_get.json()
        assert data["identity_id"] == "ID-1192"
        assert data["username"] == "john.smith"

        # Alias resolution via API
        r_alias = client.get("/api/v1/identities/jsmith")
        assert r_alias.status_code == 200
        assert r_alias.json()["identity_id"] == "ID-1192"

        # Graph
        r_graph = client.get("/api/v1/identities/ID-1192/graph")
        assert r_graph.status_code == 200
        assert "entity" in r_graph.json()

        # History / Point in time
        r_hist = client.get("/api/v1/identities/ID-1192/history")
        assert r_hist.status_code == 200
        assert r_hist.json()["entity_id"] == "ID-1192"

    def test_device_posture_and_service_identity(self):
        r_dev = client.get("/api/v1/devices/DEVICE-44/posture")
        assert r_dev.status_code == 200
        assert r_dev.json()["posture_level"] == "HEALTHY"

        r_svc = client.get("/api/v1/services/MTA-07/identity")
        assert r_svc.status_code == 200
        assert r_svc.json()["classification"] == "CRITICAL"

    def test_access_request_and_decision_endpoints(self):
        # Allow request
        payload_allow = {
            "subject_id": "ID-1192",
            "device_id": "DEVICE-44",
            "resource_id": "FORENSIC-API",
            "action": "read",
        }
        r_allow = client.post("/api/v1/access/request", json=payload_allow)
        assert r_allow.status_code == 200
        assert r_allow.json()["action"] == "FORWARD"

        # Direct decision endpoint
        r_dec = client.post("/api/v1/access/decision", json=payload_allow)
        assert r_dec.status_code == 200
        assert r_dec.json()["decision"]["decision"] == "ALLOW"

        # Deny request (unmanaged device)
        payload_deny = {
            "subject_id": "ID-1192",
            "device_id": "UNKNOWN-DEV",
            "resource_id": "FORENSIC-API",
            "action": "read",
        }
        r_deny = client.post("/api/v1/access/request", json=payload_deny)
        assert r_deny.status_code == 200
        assert r_deny.json()["action"] == "BLOCK"

    def test_policy_management_and_simulation_endpoints(self):
        r_pols = client.get("/api/v1/policies")
        assert r_pols.status_code == 200
        assert r_pols.json()["count"] >= 5

        # Validate policy
        r_val = client.post("/api/v1/policies/POL-SOC-ADMIN/validate")
        assert r_val.status_code == 200
        assert r_val.json()["valid"] is True

        # Policy Impact
        r_imp = client.get("/api/v1/policies/POL-SOC-ADMIN/impact")
        assert r_imp.status_code == 200
        assert "affected_services_count" in r_imp.json()

        # Policy Simulate
        r_sim = client.post("/api/v1/policies/POL-SOC-ADMIN/simulate")
        assert r_sim.status_code == 200
        assert "simulated_decision" in r_sim.json()

    def test_governance_and_signed_bundle_endpoints(self):
        r_dash = client.get("/api/v1/governance/dashboard")
        assert r_dash.status_code == 200
        assert r_dash.json()["active_identities"] >= 3

        r_bundle = client.get("/api/v1/governance/bundles/signed")
        assert r_bundle.status_code == 200
        assert r_bundle.json()["is_valid"] is True
        assert "digital_signature" in r_bundle.json()

    def test_jit_and_break_glass_endpoints(self):
        # JIT request
        jit_payload = {
            "identity_id": "ID-1192",
            "role_requested": "SOC_ADMIN",
            "target_resource": "FORENSIC-API",
            "justification": "Incident response test",
            "duration_minutes": 20,
        }
        r_jit_req = client.post("/api/v1/privilege/jit/request", json=jit_payload)
        assert r_jit_req.status_code == 200
        jit_id = r_jit_req.json()["request_id"]

        # JIT approve
        r_jit_app = client.post("/api/v1/privilege/jit/approve", json={"request_id": jit_id, "approver_id": "ID-2044"})
        assert r_jit_app.status_code == 200
        assert r_jit_app.json()["status"] == "ACTIVE"

        # Break-Glass emergency request
        bg_payload = {
            "requester_id": "ID-1192",
            "approver_id": "ID-2044",
            "incident_reference": "CASE-LIVE-001",
            "target_service": "MTA-07",
            "justification": "Restoring critical mail gateway routing",
            "duration_minutes": 15,
        }
        r_bg = client.post("/api/v1/privilege/emergency/request", json=bg_payload)
        assert r_bg.status_code == 200
        assert r_bg.json()["status"] == "ACTIVE"

        # Separation of duties violation check
        bg_invalid = dict(bg_payload)
        bg_invalid["approver_id"] = "ID-1192"  # Self-approval prohibited
        r_bg_inv = client.post("/api/v1/privilege/emergency/request", json=bg_invalid)
        assert r_bg_inv.status_code == 403

    def test_copilot_endpoint(self):
        r_copilot = client.post("/api/v1/copilot/identity/query", json={
            "query": "Why was session S-991 allowed?",
            "session_id": "S-991",
        })
        assert r_copilot.status_code == 200
        assert "session_id" in r_copilot.json()
