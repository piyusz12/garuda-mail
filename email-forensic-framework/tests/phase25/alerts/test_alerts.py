"""
Tests for Phase 25 Alert Intake, Deduplication, Clustering, and Multi-Indicator Correlation.
"""

import pytest
import time
from security_operations.alerts.ingest import AlertIngestEngine, Alert
from security_operations.alerts.dedup import AlertDeduplicator
from security_operations.alerts.clustering import ClusterManager
from security_operations.alerts.correlation import AlertCorrelator


def test_alert_ingest_and_normalization():
    engine = AlertIngestEngine()
    raw = {
        "source": "tls_analyzer",
        "severity": "high",
        "asset_id": "MTA-07",
        "event_type": "tls_downgrade",
        "ja4": "t12d0804h2_123456789abc_def012345678",
        "confidence": 0.95,
        "details": {"cipher": "TLS_RSA_WITH_AES_128_CBC_SHA"},
    }
    alert = engine.ingest_raw(raw, tenant_id="tenant-alpha")
    assert alert.alert_id.startswith("ALT-")
    assert alert.severity == "HIGH"
    assert alert.asset_id == "MTA-07"
    assert alert.tenant_id == "tenant-alpha"
    assert alert.details["cipher"] == "TLS_RSA_WITH_AES_128_CBC_SHA"


def test_alert_deduplication():
    dedup = AlertDeduplicator(time_window_seconds=300)
    engine = AlertIngestEngine()

    raw1 = {
        "asset_id": "MTA-07",
        "event_type": "tls_downgrade",
        "timestamp": 1000.0,
    }
    a1 = engine.ingest_raw(raw1)
    is_dup1, rep1, count1 = dedup.process(a1)
    assert not is_dup1
    assert count1 == 1

    # Same fingerprint arriving 10 seconds later
    raw2 = {
        "asset_id": "MTA-07",
        "event_type": "tls_downgrade",
        "timestamp": 1010.0,
    }
    a2 = engine.ingest_raw(raw2)
    is_dup2, rep2, count2 = dedup.process(a2)
    assert is_dup2
    assert count2 == 2


def test_multi_indicator_correlation_clustering():
    correlator = AlertCorrelator()
    engine = AlertIngestEngine()

    # Event A: Certificate Change
    a1 = engine.ingest_raw({"asset_id": "MTA-07", "event_type": "certificate_change", "severity": "HIGH"})
    res1 = correlator.process_alert(a1)

    # Event B: Rare JA4
    a2 = engine.ingest_raw({"asset_id": "MTA-07", "event_type": "new_ja4", "severity": "HIGH"})
    res2 = correlator.process_alert(a2)

    # Event C: TLS Downgrade
    a3 = engine.ingest_raw({"asset_id": "MTA-07", "event_type": "tls_downgrade", "severity": "CRITICAL"})
    res3 = correlator.process_alert(a3)

    cluster = res3["cluster"]
    assert cluster.asset_id == "MTA-07"
    assert len(cluster.alerts) == 3
    assert cluster.aggregate_severity == "CRITICAL"
    assert res3["is_incident_candidate"] is True
    assert "certificate_change" in cluster.event_types
    assert "new_ja4" in cluster.event_types
