"""Tests for Data Lineage, Data Movement Monitoring, Flow Graph, and Anomaly Detection."""

import pytest
import time
from data_security.inventory import ClassificationLevel
from data_security.flows import (
    DataFlowChannel,
    DataMovementEvent,
    DataFlowMonitor,
    DataFlowGraph,
    DataMovementAnomalyDetector,
    DataAnomalyType,
)
from data_security.lineage import (
    DataLineageGraph,
    LineageNode,
    LineageEdge,
    LineageQueryEngine,
)


def test_data_lineage_graph():
    """Verify lineage tracking and impact tracing."""
    lineage = DataLineageGraph()
    engine = LineageQueryEngine(lineage)

    # Pre-seeded graph: DATA-8821 -> PIPELINE-ETL-01 -> DATA-WH-CUSTOMERS -> API-REPORTING -> APP-DASHBOARD
    downstream = lineage.get_downstream_dependents("DATA-8821")
    assert "PIPELINE-ETL-01" in downstream
    assert "DATA-WH-CUSTOMERS" in downstream
    assert "APP-DASHBOARD" in downstream

    upstream = lineage.get_upstream_sources("APP-DASHBOARD")
    assert "API-REPORTING" in upstream
    assert "DATA-8821" in upstream

    impact = engine.trace_impact_of_breach("DATA-8821")
    assert impact["affected_downstream_count"] >= 4
    assert impact["blast_radius_rating"] == "CRITICAL"


def test_data_movement_monitor_and_graph():
    """Verify monitoring of data movement events and edge recording."""
    monitor = DataFlowMonitor()
    flow_graph = DataFlowGraph()

    event = DataMovementEvent(
        event_id="FLOW-BACKUP-01",
        source_asset_id="DATA-8821",
        destination_id="s3://backup-vault-us-east-1",
        identity_id="SVC-BACKUP-OPERATOR",
        workload_id="WORKLOAD-BACKUP-RUNNER",
        bytes_transferred=450000000,
        record_count=1250000,
        classification=ClassificationLevel.RESTRICTED,
        channel=DataFlowChannel.DATABASE_EXPORT,
        is_external_destination=False,
    )
    monitor.record_movement(event)
    events = monitor.list_events("DATA-8821")
    assert len(events) == 1
    assert events[0].event_id == "FLOW-BACKUP-01"

    flow_graph.update_with_event(event)
    flows = flow_graph.get_flows_for_asset("DATA-8821")
    assert len(flows) == 1
    assert flows[0]["destination"] == "s3://backup-vault-us-east-1"
    assert flows[0]["total_records"] == 1250000


def test_data_movement_anomaly_detection():
    """Verify detection of volume anomalies, unexpected identities, and external egress."""
    detector = DataMovementAnomalyDetector()

    # Normal baseline event (10,000 records to approved destination)
    normal_event = DataMovementEvent(
        event_id="FLOW-NORM-01",
        source_asset_id="DATA-8821",
        destination_id="internal.vault.garuda",
        channel=DataFlowChannel.API_HTTP,
        workload_id="WORKLOAD-ETL-STANDARD",
        identity_id="SERVICE-91",
        bytes_transferred=500000,
        record_count=10000,
        classification=ClassificationLevel.RESTRICTED,
        is_external_destination=False,
    )
    anomalies_norm = detector.inspect_flow_event(normal_event)
    assert len(anomalies_norm) == 0

    # Section 29.54 & 29.86 scenario:
    # Baseline: ~10,000 records/day.
    # Observed: 900,000 records to external destination by unexpected workload/identity
    attack_event = DataMovementEvent(
        event_id="FLOW-EXFIL-91",
        source_asset_id="DATA-8821",
        destination_id="external.example",
        channel=DataFlowChannel.API_HTTP,
        workload_id="WORKLOAD-991",
        identity_id="SERVICE-91",
        bytes_transferred=185000000,
        record_count=900000,
        classification=ClassificationLevel.RESTRICTED,
        is_external_destination=True,
    )
    anomalies_attack = detector.inspect_flow_event(attack_event)
    assert len(anomalies_attack) >= 2

    types = [a.anomaly_type for a in anomalies_attack]
    assert DataAnomalyType.VOLUME_ANOMALY in types
    assert DataAnomalyType.DESTINATION_ANOMALY in types
