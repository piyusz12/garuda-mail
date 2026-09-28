"""Tests for Data Graph, Effective Access Calculation, and Data Minimization Analysis."""

import pytest
from data_graph import (
    DataGraph,
    DataGraphNode,
    DataGraphNodeType,
    DataGraphEdge,
    DataGraphEdgeType,
)
from data_security.access import (
    DataAccessGraph,
    DataAccessBinding,
    EffectiveAccessCalculator,
    DataMinimizationAnalyzer,
    MinimizationFindingSeverity,
)


def test_data_graph_traversal():
    """Verify graph path finding across identity -> workload -> API -> DB -> Data asset."""
    graph = DataGraph()
    # Nodes are pre-seeded in DataGraph, but we can verify finding path from USER-1192 to DATA-8821
    paths = graph.find_paths(start_id="USER-1192", target_id="DATA-8821")
    assert len(paths) >= 1
    p = paths[0]
    assert p.start_node == "USER-1192"
    assert p.target_node == "DATA-8821"
    assert "DATABASE-21" in p.to_dict()["chain_description"]

    # Verify custom node and edge addition
    n_custom = DataGraphNode("WORKLOAD-NEW-99", DataGraphNodeType.WORKLOAD, "Custom Processor")
    graph.add_node(n_custom)
    e_custom = DataGraphEdge("EDGE-NEW-99", "WORKLOAD-NEW-99", "DATA-8821", DataGraphEdgeType.READS)
    graph.add_edge(e_custom)

    new_paths = graph.find_paths(start_id="WORKLOAD-NEW-99", target_id="DATA-8821")
    assert len(new_paths) == 1
    assert new_paths[0].start_node == "WORKLOAD-NEW-99"


def test_effective_access_calculation():
    """Verify calculation of direct, workload-derived, and transitive access."""
    calculator = EffectiveAccessCalculator()
    report = calculator.calculate_effective_access("DATA-8821")

    assert report.target_asset_id == "DATA-8821"
    assert "DBA-ADMIN-01" in report.direct_identities
    assert "SERVICE-91" in report.workload_derived_identities
    assert len(report.transitive_access_paths) > 0
    assert report.total_effective_identities_count >= 2


def test_data_minimization_excessive_access():
    """Verify detection of workloads querying columns outside their approved contract."""
    analyzer = DataMinimizationAnalyzer()

    # Query matching approved contract (MTA-07 needs customer_id, email)
    finding_clean = analyzer.audit_query_access(
        service_id="MTA-07",
        asset_id="DATA-8821",
        requested_columns=["customer_id", "email"],
    )
    assert finding_clean is None

    # Query accessing excessive sensitive columns (payment_token, billing_address)
    finding_violation = analyzer.audit_query_access(
        service_id="MTA-07",
        asset_id="DATA-8821",
        requested_columns=["customer_id", "email", "payment_token", "billing_address"],
    )
    assert finding_violation is not None
    assert "payment_token" in finding_violation.unnecessary_columns
    assert finding_violation.severity == MinimizationFindingSeverity.HIGH
    assert "EXCESSIVE_DATA_ACCESS" in finding_violation.description
