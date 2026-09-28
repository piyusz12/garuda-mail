"""
Tests for Phase 23 MITRE ATT&CK Mapping, Coverage Matrix, Gap Discovery, and Feedback Loops.
"""
import pytest
from coverage.attack_mapping import MITRE_ATTACK_CATALOG
from coverage.detections import DetectionCoverageEngine
from coverage.gaps import DetectionGapDiscoveryEngine
from feedback.analyst_labels import AnalystFeedbackCollector
from feedback.learning import DetectionLearningEngine
from detection.models import DetectionRule

def test_mitre_attack_catalog():
    assert "T1573.002" in MITRE_ATTACK_CATALOG
    mapping = MITRE_ATTACK_CATALOG["T1573.002"]
    assert mapping.tactic == "Command and Control"
    assert "DET-TLS-001" in mapping.mapped_detection_ids

def test_multidimensional_coverage():
    rules = [
        DetectionRule(
            detection_id="DET-TLS-001",
            name="TLS Downgrade",
            description="",
            logic={},
            tags=["TLS"],
            data_sources=["tls_events"]
        ),
        DetectionRule(
            detection_id="DET-STARTTLS-001",
            name="STARTTLS Stripping",
            description="",
            logic={},
            tags=["SMTP"],
            data_sources=["sessions"]
        )
    ]
    coverage = DetectionCoverageEngine.calculate_multidimensional_coverage(rules)
    assert "protocol_coverage" in coverage
    assert "behavior_coverage" in coverage
    assert coverage["protocol_coverage"].categories_covered >= 2

def test_detection_gap_discovery():
    incident_telemetry = [
        {"asset": "MTA-07", "starttls_stripped": True}
    ]
    # Engine only fired DET-OTHER
    gaps = DetectionGapDiscoveryEngine.analyze_incident_coverage(
        incident_id="INC-01",
        incident_telemetry=incident_telemetry,
        actual_triggered_rule_ids=["DET-OTHER"],
        expected_behaviors=["STARTTLS_STRIP"]
    )
    assert len(gaps) >= 1
    assert "STARTTLS" in gaps[0].observed_attack_behavior

def test_analyst_feedback_and_learning():
    collector = AnalystFeedbackCollector()
    rec1 = collector.record_feedback("FND-01", "DET-01", "FALSE_POSITIVE", "analyst-1", "Dev test", {"asset": "MTA-07"})
    rec2 = collector.record_feedback("FND-02", "DET-01", "FALSE_POSITIVE", "analyst-2", "Dev test", {"asset": "MTA-07"})
    rec3 = collector.record_feedback("FND-03", "DET-01", "FALSE_POSITIVE", "analyst-3", "Staging sync", {"asset": "MTA-08"})

    learning = DetectionLearningEngine(collector)
    cluster = learning.analyze_false_positives("DET-01")
    assert cluster is not None
    assert cluster.total_false_positives == 3
    assert cluster.by_asset["MTA-07"] > 60.0

def test_recurrence_watcher():
    learning = DetectionLearningEngine()
    watcher = learning.create_remediation_watcher("FND-REMED", "MTA-07", "TLS 1.1", grace_days=90)
    assert watcher.is_active is True

    # Check matching recurring telemetry
    triggered = learning.check_telemetry_for_recurrence("MTA-07", "Observed TLS 1.1 on port 25")
    assert len(triggered) == 1
    assert triggered[0].recurrence_count == 1
