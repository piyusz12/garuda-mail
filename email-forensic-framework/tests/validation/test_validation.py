"""
Tests for Phase 23 Validation Datasets, Metrics, Simulation, Backtesting, and Regression.
"""
import pytest
from validation.datasets import ValidationDatasetRepository
from validation.metrics import DetectionPerformanceMetrics
from validation.simulation import DetectionSimulator
from validation.backtest import DetectionBacktester
from validation.regression import DetectionRegressionTester
from detection.models import DetectionRule
from detection.engine import DetectionEngine

def test_validation_metrics_calculation():
    metrics = DetectionPerformanceMetrics(
        detection_id="DET-TEST",
        version="1.0",
        true_positives=9,
        false_positives=1,
        true_negatives=80,
        false_negatives=2,
        total_samples=92
    )
    assert metrics.precision == 0.9  # 9 / 10
    assert metrics.recall == 0.818   # 9 / 11
    assert metrics.f1_score > 0.8

def test_detection_simulation():
    engine = DetectionEngine()
    rule = DetectionRule(
        detection_id="DET-TLS-001",
        name="Legacy TLS",
        description="",
        rule_type="SIGNATURE",
        logic={"conditions": [{"field": "tls_version", "op": "IN", "value": ["TLS 1.1", "TLS 1.0"]}]},
        status="PRODUCTION"
    )
    engine.register_rule(rule)

    sim_res = DetectionSimulator.simulate_tls_downgrade_scenario(engine)
    assert sim_res.passed is True
    assert "DET-TLS-001" in sim_res.actual_detections

def test_detection_backtesting():
    rule = DetectionRule(detection_id="DET-TLS-001", name="Legacy TLS", description="", logic={})
    report = DetectionBacktester.backtest_rule(rule, None)
    assert report.rule_id == "DET-TLS-001"
    assert len(report.windows) == 4
    labels = [w.window_label for w in report.windows]
    assert "30d" in labels and "3y" in labels

def test_detection_regression_testing():
    base_rule = DetectionRule(
        detection_id="DET-REG-01",
        version="1.0",
        name="Base Rule",
        description="",
        rule_type="SIGNATURE",
        logic={"conditions": [{"field": "tls_version", "op": "IN", "value": ["TLS 1.0", "TLS 1.1"]}]}
    )
    # New rule has tighter logic that drops true positives
    new_rule = DetectionRule(
        detection_id="DET-REG-01",
        version="1.1",
        name="New Rule",
        description="",
        rule_type="SIGNATURE",
        logic={"conditions": [{"field": "tls_version", "op": "=", "value": "TLS 1.0"}]} # Excludes TLS 1.1!
    )
    dataset = ValidationDatasetRepository.get_tls_test_dataset()
    comparison = DetectionRegressionTester.test_version_regression(base_rule, new_rule, dataset)
    assert comparison.regression_detected is True
    assert len(comparison.reasons) > 0
