"""
Tests for Phase 27 — Identity Fabric, Normalization, Graph, Posture, Risk & Lifecycle.
"""

import time
import pytest
from datetime import datetime, timezone

from identity.ingestion import (
    UserIdentity,
    UserIdentityRepository,
    IdentityStatus,
    DeviceIdentity,
    DeviceIdentityRepository,
    DeviceType,
    DeviceComplianceStatus,
    ServiceIdentity,
    ServiceIdentityRepository,
    ResourceClassification,
    WorkloadIdentity,
    WorkloadIdentityRepository,
)
from identity.normalization import (
    IdentityResolver,
    CertificateIdentityBinding,
    SessionIdentityBinding,
)
from identity.graph import (
    IdentityNode,
    IdentityNodeType,
    IdentityEdge,
    IdentityEdgeType,
    TemporalIdentityGraph,
)
from identity.posture import (
    DevicePostureState,
    DevicePostureLevel,
    DevicePostureEvaluator,
    IdentityPostureState,
    IdentityPostureLevel,
    IdentityPostureEvaluator,
    ServicePostureState,
    ServicePostureEvaluator,
)
from identity.risk import (
    IdentityBehaviorBaseline,
    BehavioralAnalyticsEngine,
    SessionRiskScore,
    SessionRiskLevel,
    SessionRiskEngine,
    IdentityRiskAssessment,
    IdentityRiskLevel,
    IdentityRiskEngine,
)
from identity.lifecycle import (
    IdentityLifecycleManager,
    IdentityLifecycleError,
    AccessGrant,
    AccessState,
    AccessLifecycleManager,
    DeviceLifecycleManager,
)


class TestIdentityIngestion:
    def test_user_repository_defaults_and_registration(self):
        repo = UserIdentityRepository()
        assert repo.get("ID-1192") is not None
        assert repo.get("ID-1192").username == "john.smith"

        new_user = UserIdentity(
            identity_id="ID-9999",
            username="test.user",
            email="test.user@enterprise.org",
            full_name="Test User",
            department="QA",
            title="Tester",
            groups=["testers"],
            roles=["TESTER_ROLE"],
        )
        repo.register(new_user)
        assert repo.get("ID-9999") is not None
        assert repo.get_by_username("test.user") is not None
        assert repo.get_by_username("test.user@enterprise.org") is not None

    def test_device_repository_defaults_and_registration(self):
        repo = DeviceIdentityRepository()
        assert repo.get("DEVICE-44") is not None
        assert repo.get("DEVICE-44").managed is True
        assert repo.get("DEVICE-44").device_type == DeviceType.LAPTOP

        new_dev = DeviceIdentity(
            device_id="DEV-TEST-01",
            hostname="test-host.local",
            serial_number="SN-TEST-001",
            owner_identity_id="ID-9999",
            device_type=DeviceType.MOBILE,
            operating_system="iOS 18.0",
            os_version="18.0",
            managed=False,
            compliance_status=DeviceComplianceStatus.NON_COMPLIANT,
        )
        repo.register(new_dev)
        assert repo.get("DEV-TEST-01") is not None
        assert repo.get("DEV-TEST-01").managed is False

    def test_service_repository_defaults_and_classification(self):
        repo = ServiceIdentityRepository()
        mta = repo.get("MTA-07")
        assert mta is not None
        assert mta.classification == ResourceClassification.CRITICAL
        assert "security-ops" in mta.allowed_source_groups

        new_svc = ServiceIdentity(
            service_id="SVC-LOGS",
            service_name="Central Log Store",
            owner_identity_id="ID-2044",
            environment="production",
            namespace="logging",
            classification=ResourceClassification.INTERNAL,
            certificate_id=None,
            port=443,
            protocol="https",
            endpoint="logs.internal:443",
        )
        repo.register(new_svc)
        assert repo.get("SVC-LOGS") is not None
        assert repo.get("SVC-LOGS").classification == ResourceClassification.INTERNAL

    def test_workload_repository(self):
        repo = WorkloadIdentityRepository()
        w = repo.get("WORKLOAD-MTA-RELAY-01")
        assert w is not None
        assert "spiffe://" in w.spiffe_id
        assert w.service_id == "MTA-07"


class TestIdentityNormalization:
    def test_alias_resolution(self):
        resolver = IdentityResolver()
        assert resolver.resolve("john.smith") == "ID-1192"
        assert resolver.resolve("jsmith") == "ID-1192"
        assert resolver.resolve("john.smith@enterprise.org") == "ID-1192"
        assert resolver.resolve("EMP-1192") == "ID-1192"

        # Register custom alias
        resolver.register_alias("j.smith.sec", "ID-1192")
        assert resolver.resolve("j.smith.sec") == "ID-1192"

        # Direct ID preserves
        assert resolver.resolve("ID-1192") == "ID-1192"
        assert resolver.resolve("id-1192") == "ID-1192"

    def test_certificate_and_session_bindings(self):
        cert_bind = CertificateIdentityBinding(
            certificate_id="CERT-2026-PRIMARY",
            identity_id="ID-2044",
            binding_type="SUBJECT_ALTERNATIVE_NAME",
            valid_from="2026-01-01T00:00:00Z",
            valid_to="2027-01-01T00:00:00Z",
        )
        assert cert_bind.is_active is True
        assert cert_bind.to_dict()["certificate_id"] == "CERT-2026-PRIMARY"

        sess_bind = SessionIdentityBinding(
            session_id="SESS-101",
            source_identity_id="ID-1192",
            source_device_id="DEVICE-44",
            destination_service_id="MTA-07",
            source_ip="10.200.1.44",
        )
        assert sess_bind.to_dict()["session_id"] == "SESS-101"


class TestTemporalIdentityGraph:
    def test_graph_seed_and_point_in_time(self):
        graph = TemporalIdentityGraph()
        node = graph.get_node("ID-1192")
        assert node is not None
        assert node.node_type == IdentityNodeType.PERSON

        # Query point-in-time
        now = time.time()
        pit = graph.point_in_time_query("ID-1192", now)
        assert pit["entity_id"] == "ID-1192"
        assert len(pit["active_relationships"]) >= 1

    def test_graph_access_path_tracing(self):
        graph = TemporalIdentityGraph()
        path = graph.trace_access_path("ID-1192", "MTA-07")
        assert len(path) >= 2
        assert path[0] == "ID-1192"
        assert path[-1] == "MTA-07"


class TestPostureAssessment:
    def test_device_posture_healthy_vs_unmanaged(self):
        healthy = DevicePostureEvaluator.evaluate(
            device_id="DEVICE-44",
            managed=True,
            disk_encrypted=True,
            edr_active=True,
            os_patched=True,
            certificate_valid=True,
        )
        assert healthy.posture_level == DevicePostureLevel.HEALTHY
        assert healthy.posture_score >= 0.85

        unmanaged = DevicePostureEvaluator.evaluate(
            device_id="DEVICE-UNMANAGED",
            managed=False,
            disk_encrypted=False,
        )
        assert unmanaged.posture_level == DevicePostureLevel.NONCOMPLIANT
        assert unmanaged.posture_score < 0.50

    def test_identity_posture_and_service_posture(self):
        id_posture = IdentityPostureEvaluator.evaluate(
            identity_id="ID-1192",
            mfa_enforced=True,
            password_age_days=15,
            failed_logins_24h=0,
        )
        assert id_posture.posture_level == IdentityPostureLevel.HEALTHY
        assert id_posture.posture_score >= 0.90

        srv_posture = ServicePostureEvaluator.evaluate(
            service_id="MTA-07",
            mtls_enforced=True,
            cert_valid=True,
            cert_expiry_days=180,
            pqc_compliant=True,
        )
        assert srv_posture.is_compliant is True
        assert srv_posture.posture_score == 1.0


class TestRiskEngines:
    def test_behavioral_baseline_and_session_risk(self):
        b_engine = BehavioralAnalyticsEngine()
        baseline = IdentityBehaviorBaseline(
            identity_id="ID-1192",
            known_devices={"DEVICE-44"},
            known_services={"MTA-07", "FORENSIC-API"},
            known_ja4_fingerprints={"t13d1516h2_8daaf6152771_000000000000"},
            typical_active_hours_utc=set(range(8, 20)),
        )
        b_engine.save_baseline(baseline)

        sess_engine = SessionRiskEngine(behavioral_engine=b_engine)
        # Normal session
        normal_risk = sess_engine.evaluate_session(
            session_id="S-NORM",
            identity_id="ID-1192",
            device_id="DEVICE-44",
            service_id="MTA-07",
            ja4="t13d1516h2_8daaf6152771_000000000000",
            destination_ip="10.200.1.7",
            destination_port=25,
            tls_version="TLS 1.3",
            cert_valid=True,
        )
        assert normal_risk.risk_level in (SessionRiskLevel.LOW, SessionRiskLevel.MEDIUM)

        # Anomalous session: new device, unexpected service, bad TLS
        anom_risk = sess_engine.evaluate_session(
            session_id="S-ANOM",
            identity_id="ID-1192",
            device_id="DEVICE-ROGUE",
            service_id="PAYROLL-DB",
            ja4="unknown_ja4_fingerprint",
            tls_version="TLS 1.0",
            cert_valid=False,
        )
        assert anom_risk.risk_score > normal_risk.risk_score
        assert anom_risk.risk_level in (SessionRiskLevel.HIGH, SessionRiskLevel.CRITICAL)

    def test_identity_risk_calculation(self):
        posture = DevicePostureEvaluator.evaluate(device_id="DEV-1", managed=False)
        sess_risk = SessionRiskScore(
            session_id="S-1",
            risk_score=85.0,
            risk_level=SessionRiskLevel.HIGH,
            factors=["Unusual JA4"],
        )
        id_risk = IdentityRiskEngine.calculate_risk(
            identity_id="ID-1192",
            device_posture=posture,
            session_risk=sess_risk,
            is_privileged=True,
        )
        assert id_risk.overall_score >= 50.0
        assert id_risk.risk_level in (IdentityRiskLevel.ELEVATED, IdentityRiskLevel.HIGH, IdentityRiskLevel.CRITICAL)


class TestIdentityLifecycle:
    def test_identity_lifecycle_state_machine(self):
        mgr = IdentityLifecycleManager()
        user = UserIdentity(
            identity_id="ID-USER-X",
            username="user.x",
            email="user.x@enterprise.org",
            full_name="User X",
            department="Operations",
            title="Operator",
            status=IdentityStatus.PENDING_VERIFICATION,
        )

        mgr.transition_state(user, IdentityStatus.ACTIVE, "admin", "onboarding complete")
        assert user.status == IdentityStatus.ACTIVE

        mgr.transition_state(user, IdentityStatus.SUSPENDED, "admin", "suspicious activity")
        assert user.status == IdentityStatus.SUSPENDED

        mgr.transition_state(user, IdentityStatus.ACTIVE, "admin", "investigation cleared")
        assert user.status == IdentityStatus.ACTIVE

        mgr.transition_state(user, IdentityStatus.DEACTIVATED, "admin", "resignation")
        assert user.status == IdentityStatus.DEACTIVATED

        # Illegal transition
        with pytest.raises(IdentityLifecycleError):
            mgr.transition_state(user, IdentityStatus.SUSPENDED, "admin", "cannot suspend deactivated")

    def test_access_lifecycle_grants(self):
        mgr = AccessLifecycleManager()
        grant = mgr.grant_access(
            identity_id="ID-1192",
            resource_id="MTA-07",
            action="administer",
            granted_by="admin",
            duration_seconds=7200,
        )
        assert grant.is_valid_now() is True
        assert grant.state == AccessState.ACTIVE

        revoked = mgr.revoke_access(grant.grant_id, actor="admin", reason="access cleanup")
        assert revoked.state == AccessState.REVOKED
        assert revoked.is_valid_now() is False
