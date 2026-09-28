"""
Unit & Integration Tests for Phase 28 Graph & Simulation Modules.
Tests Cloud Attack Path Analysis, Temporal Graph Diffing, Policy Simulation, and Blast Radius.
"""
import pytest
from cloud_graph.nodes import CloudNode, CloudNodeType
from cloud_graph.edges import CloudEdge, CloudEdgeType
from cloud_graph.paths import CloudAttackPathAnalyzer
from cloud_graph.temporal import TemporalCloudGraph
from simulation.policies import CloudPolicySimulator
from simulation.kubernetes import KubernetesTwinSimulator
from kubernetes.workloads import K8sWorkload, WorkloadType


def test_cloud_attack_path_discovery():
    analyzer = CloudAttackPathAnalyzer()
    paths = analyzer.find_attack_paths("USER-1192", "DATABASE-A")

    assert len(paths) >= 1
    p = paths[0]
    assert p.start_node_id == "USER-1192"
    assert p.target_node_id == "DATABASE-A"
    assert p.length == 5
    assert p.path_risk_score > 0.0

    chain = [p.start_node_id] + [s.to_node for s in p.steps]
    assert chain == ["USER-1192", "CLOUD-ROLE-22", "K8S-CLUSTER-01", "NAMESPACE-A", "WORKLOAD-991", "DATABASE-A"]


def test_effective_access_to_database():
    analyzer = CloudAttackPathAnalyzer()
    effective_paths = analyzer.find_effective_access_to_resource("DATABASE-A")
    assert len(effective_paths) >= 1
    # Should include both USER-1192 and WORKLOAD-991 as reaching DATABASE-A
    start_nodes = [p.start_node_id for p in effective_paths]
    assert "USER-1192" in start_nodes
    assert "WORKLOAD-991" in start_nodes


def test_temporal_graph_snapshot_diff():
    temporal = TemporalCloudGraph()
    nodes_v1 = {
        "N1": CloudNode("N1", CloudNodeType.USER, "user1"),
        "N2": CloudNode("N2", CloudNodeType.WORKLOAD, "w1"),
    }
    edges_v1 = {"N1": [CloudEdge("E1", "N1", "N2", CloudEdgeType.ACCESSES)]}

    temporal.capture_snapshot("SNAP-1", "Base State", nodes_v1, edges_v1)

    # In V2, add a new unapproved external egress node and edge
    nodes_v2 = dict(nodes_v1)
    nodes_v2["N3"] = CloudNode("N3", CloudNodeType.DATABASE, "external-c2-db")
    edges_v2 = dict(edges_v1)
    edges_v2["N2"] = [CloudEdge("E2", "N2", "N3", CloudEdgeType.COMMUNICATES_WITH)]

    temporal.capture_snapshot("SNAP-2", "Post-Incident State", nodes_v2, edges_v2)

    diff = temporal.diff_snapshots("SNAP-1", "SNAP-2")
    assert diff["has_topology_drift"] is True
    assert "N3" in diff["added_nodes"]
    assert any(e["source"] == "N2" and e["target"] == "N3" for e in diff["added_edges"])


def test_cloud_policy_simulator_detects_breaking_change():
    simulator = CloudPolicySimulator()

    # Simulation that cuts critical dns / healthz flows
    res = simulator.simulate_network_policy_change(
        policy_name="strict-deny-all",
        namespace="email-ingress",
        current_allowed_flows=["garuda-mta -> 10.0.1.10:25", "garuda-mta -> kube-dns:53", "garuda-mta -> /healthz:8080"],
        proposed_allowed_flows=["garuda-mta -> 10.0.1.10:25"],  # cuts dns and healthz!
        active_workloads=["WORKLOAD-991"],
    )
    assert res.verdict == "BREAKING_CHANGE"
    assert len(res.new_denials) == 2
    assert any("healthz" in d or "dns" in d for d in res.new_denials)


def test_kubernetes_twin_simulator_quarantine_blast_radius():
    k8s_twin = KubernetesTwinSimulator()
    workload = K8sWorkload(
        workload_id="WORKLOAD-991",
        name="mta-edge-relay",
        workload_type=WorkloadType.DEPLOYMENT,
        cluster_id="CLUSTER-PROD-01",
        namespace="email-ingress",
        image_tag="garuda/mta-edge:v2.4.1",
        image_digest="sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222",
        replica_count=4,
    )
    impact = k8s_twin.simulate_quarantine(workload)
    assert impact.action_simulated == "QUARANTINE"
    assert impact.sla_impact == "DEGRADED"
    assert impact.estimated_downtime_seconds == 0  # Replicas absorb traffic
    assert "Standby replica active" in impact.mitigation_strategy
