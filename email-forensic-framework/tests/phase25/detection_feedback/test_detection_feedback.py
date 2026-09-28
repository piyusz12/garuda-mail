"""
Tests for Phase 25 Closed-Loop Feedback, Drift Tracking, Historical Replay, and Threat-Hunt Promotion.
"""

import pytest
from security_operations.feedback.labels import FeedbackLabelStore, AnalystLabel
from security_operations.feedback.performance import DetectionPerformanceMetrics
from security_operations.feedback.drift import DetectionDriftTracker, ModelDriftTracker
from security_operations.feedback.learning import ClosedLoopLearningEngine
from detection_engineering.rules.models import DetectionRuleRepository
from detection_engineering.replay.engine import HistoricalReplayEngine
from detection_engineering.deployment.promoter import ThreatHuntPromoter


def test_feedback_and_metrics_calculation():
    store = FeedbackLabelStore()
    store.record_label("RULE-TLS-001", "CASE-01", AnalystLabel.TP, "analyst-1")
    store.record_label("RULE-TLS-001", "CASE-02", AnalystLabel.TP, "analyst-1")
    store.record_label("RULE-TLS-001", "CASE-03", AnalystLabel.FP, "analyst-2")

    metrics = DetectionPerformanceMetrics(store)
    perf = metrics.calculate_metrics("RULE-TLS-001")
    assert perf["total_alerts"] == 3
    assert perf["tp_count"] == 2
    assert perf["fp_count"] == 1
    assert round(perf["precision"], 2) == 0.67


def test_detection_and_model_drift():
    # Detection drift
    trend = [0.04, 0.08, 0.19, 0.32]
    d_res = DetectionDriftTracker.evaluate_drift("RULE-TLS-001", trend)
    assert d_res["has_drift"] is True
    assert d_res["status"] == "DETECTION_DRIFT"

    # Model feature drift
    baseline = {"feature_a": 0.5, "feature_b": 0.5}
    shifted = {"feature_a": 0.9, "feature_b": 0.1}
    m_res = ModelDriftTracker.evaluate_feature_drift("MODEL-AI-01", baseline, shifted)
    assert m_res["has_drift"] is True
    assert m_res["status"] == "MODEL_REVIEW_REQUIRED"


def test_historical_replay_and_hunt_promotion():
    repo = DetectionRuleRepository()
    promoter = ThreatHuntPromoter(repo)

    res = promoter.promote_hunt_finding(
        hunt_id="HUNT-JA4-77",
        hypothesis_title="Anomalous JA4 in corporate SMTP relay",
        query_dsl="EVENT == 'client_hello' AND ja4 == 'rare_hash'",
        severity="HIGH",
    )
    assert res["hunt_id"] == "HUNT-JA4-77"
    assert res["status"] in ("PRODUCTION", "CANARY_REJECTED")
    assert res["replay_results"]["events_replayed"] > 0
