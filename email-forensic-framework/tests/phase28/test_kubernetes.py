"""
Unit & Integration Tests for Phase 28 Kubernetes Modules.
Tests Cluster Inventory, Workload Modeling, Admission Control, RBAC Analysis, and Network Policies.
"""
import pytest
from kubernetes.clusters import K8sCluster, K8sClusterRepository, ClusterPostureLevel
from kubernetes.workloads import K8sWorkload, K8sWorkloadRepository, WorkloadType
from kubernetes.admission import AdmissionController, AdmissionReviewRequest
from kubernetes.rbac import RBACAnalyzer, K8sRoleBinding, RBACPolicyRule
from kubernetes.network_policy import NetworkPolicyEvaluator, K8sNetworkPolicy, NetworkPolicyRule


def test_kubernetes_workload_repository():
    repo = K8sWorkloadRepository()
    workload = repo.get("WORKLOAD-991")
    assert workload is not None
    assert workload.name == "mta-edge-relay"
    assert workload.cluster_id == "CLUSTER-PROD-01"
    assert workload.is_privileged is False
    assert workload.replica_count == 4


def test_admission_controller_unsigned_image():
    controller = AdmissionController()

    # Request with an unsigned image in production namespace
    req_denied = AdmissionReviewRequest(
        request_id="ADM-REQ-001",
        namespace="email-ingress",
        image_tag="docker.io/unverified/debug-tool:v1",
        image_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        is_privileged=False,
        service_account="sa-pipeline",
    )
    resp_denied = controller.evaluate_admission(req_denied)
    assert resp_denied.allowed is False
    assert "unsigned" in resp_denied.reason.lower() or "signature" in resp_denied.reason.lower() or "untrusted" in resp_denied.reason.lower()

    # Request with a verified signed production image
    req_allowed = AdmissionReviewRequest(
        request_id="ADM-REQ-002",
        namespace="email-ingress",
        image_tag="garuda/mta-edge:v2.4.1",
        image_digest="sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222",
        is_privileged=False,
        service_account="sa-mta-pipeline",
    )
    resp_allowed = controller.evaluate_admission(req_allowed)
    assert resp_allowed.allowed is True


def test_admission_controller_privileged_container_denied():
    controller = AdmissionController()
    req_privileged = AdmissionReviewRequest(
        request_id="ADM-REQ-003",
        namespace="email-ingress",
        image_tag="garuda/mta-edge:v2.4.1",
        image_digest="sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222",
        is_privileged=True,  # Violates pod security standard
        service_account="sa-mta-pipeline",
    )
    resp = controller.evaluate_admission(req_privileged)
    assert resp.allowed is False
    assert "privileged" in resp.reason.lower()


def test_rbac_analyzer_excessive_privilege():
    analyzer = RBACAnalyzer()
    admin_binding = K8sRoleBinding(
        binding_id="RB-OVERPERM-01",
        name="wildcard-cluster-admin-binding",
        subject_name="USER-1192",
        subject_kind="User",
        role_name="cluster-admin",
        namespace="*",
        rules=[
            RBACPolicyRule(api_groups=["*"], resources=["*"], verbs=["*"])
        ],
    )
    findings = analyzer.analyze_binding(admin_binding)
    assert len(findings) >= 1
    assert any("wildcard" in f.title.lower() or "cluster-admin" in f.title.lower() or "excessive" in f.title.lower() for f in findings)


def test_network_policy_evaluation():
    evaluator = NetworkPolicyEvaluator()
    isolated_policy = K8sNetworkPolicy(
        policy_id="NP-MAIL-INGRESS",
        name="restrict-mail-ingress",
        namespace="email-ingress",
        pod_selector={"app": "mta-edge-relay"},
        ingress_rules=[
            NetworkPolicyRule(
                ports=[25, 465, 587],
                allowed_sources=["10.0.0.0/16"],
            )
        ],
        egress_rules=[
            NetworkPolicyRule(
                ports=[5432, 8443],
                allowed_destinations=["10.0.2.0/24"],
            )
        ],
    )
    evaluator.register_policy(isolated_policy)

    # Allowed egress to database port 5432
    verdict_allowed = evaluator.check_flow(
        namespace="email-ingress",
        source_pod_labels={"app": "mta-edge-relay"},
        destination_ip="10.0.2.5",
        destination_port=5432,
        is_egress=True,
    )
    assert verdict_allowed is True

    # Blocked egress to unexpected external C2 port 4444
    verdict_blocked = evaluator.check_flow(
        namespace="email-ingress",
        source_pod_labels={"app": "mta-edge-relay"},
        destination_ip="198.51.100.42",
        destination_port=4444,
        is_egress=True,
    )
    assert verdict_blocked is False
