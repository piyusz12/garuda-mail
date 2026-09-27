"""
Tests for Phase 23 Detection Engineering, Scoring, Evaluator, Correlation, and Versioning.
"""
import pytest
from datetime import datetime, timezone

from detection.models import DetectionRule, SeverityDimensions, Finding
from detection.scoring import DetectionScorer
from detection.evaluator import DetectionEvaluator
from detection.correlation import CorrelationEngine, SequenceDefinition, TemporalStage
from detection.versioning import DetectionVersioningEngine
from detection.engine import DetectionEngine

def test_severity_dimensions_scoring():
    dims = SeverityDimensions(impact=0.8, exposure=0.7, confidence=0.9, persistence=0.8, scope=0.5)
    score = dims.calculate_score()
    assert 0.0 <= score <= 1.0
    qual = dims.to_qualitative()
    assert qual in ("HIGH", "CRITICAL")

def test_confidence_decomposition():
    decomp = DetectionScorer.decompose_confidence(
        historical_support=0.9,
        behavioral_support=0.85,
        graph_support=0.8,
        intelligence_support=0.75,
        counter_evidence=0.0
    )
    assert decomp["net_confidence"] >= 0.7
    assert decomp["counter_evidence"] == 0.0

    # With high counter-evidence
    d_counter = DetectionScorer.decompose_confidence(
        historical_support=0.9,
        behavioral_support=0.85,
        counter_evidence=0.8
    )
    assert d_counter["net_confidence"] < decomp["net_confidence"]

def test_model_rule_fusion():
    fused = DetectionScorer.fuse_models(
        rule_confidence=0.85,
        anomaly_score=0.92,
        historical_similarity=0.95,
        graph_context_score=0.80
    )
    assert "components" in fused
    assert fused["fused_risk"] >= 0.85

def test_evaluator_signature_and_threshold():
    # Signature test
    logic_sig = {"field": "tls_version", "op": "IN", "value": ["TLS 1.0", "TLS 1.1"]}
    match, exp = DetectionEvaluator.evaluate("SIGNATURE", logic_sig, {"tls_version": "TLS 1.1"})
    assert match is True
    assert len(exp) > 0

    no_match, _ = DetectionEvaluator.evaluate("SIGNATURE", logic_sig, {"tls_version": "TLS 1.3"})
    assert no_match is False

    # Threshold test
    logic_thresh = {"metric_field": "session_count", "op": ">", "threshold": 10}
    t_match, _ = DetectionEvaluator.evaluate("THRESHOLD", logic_thresh, {"session_count": 15}, context={"session_count": 15})
    assert t_match is True

def test_correlation_multi_stage_sequence():
    engine = CorrelationEngine()
    seq = SequenceDefinition(
        sequence_id="SEQ-TEST",
        name="Test Attack Sequence",
        stages=[
            TemporalStage(stage_name="STAGE1", event_type="CERT_CHANGE", match_criteria={"changed": True}),
            TemporalStage(stage_name="STAGE2", event_type="TLS_DOWNGRADE", match_criteria={"tls": "TLS 1.1"})
        ]
    )
    engine.register_sequence(seq)

    # Ingest event 1
    engine.ingest_event("MTA-01", "CERT_CHANGE", {"changed": True})
    # Ingest event 2
    matches = engine.ingest_event("MTA-01", "TLS_DOWNGRADE", {"tls": "TLS 1.1"})
    assert len(matches) == 1
    assert matches[0].is_complete is True
    assert matches[0].sequence_id == "SEQ-TEST"

def test_alert_clustering_and_deduplication():
    engine = CorrelationEngine()
    is_new, cluster_id, count = engine.cluster_and_deduplicate("DET-001", "MTA-07", "EVT-1")
    assert is_new is True
    assert count == 1

    # Second event in cluster
    is_new2, cluster_id2, count2 = engine.cluster_and_deduplicate("DET-001", "MTA-07", "EVT-2")
    assert is_new2 is False
    assert cluster_id2 == cluster_id
    assert count2 == 2

def test_rule_versioning_and_promotion_pipeline():
    v_engine = DetectionVersioningEngine()
    rule = DetectionRule(
        detection_id="DET-TEST-01",
        name="Test Rule",
        description="Testing versioning",
        logic={"threshold": 10},
        version="1.0",
        status="DRAFT"
    )
    v_engine.register_rule(rule)

    # Step-wise promotion: DRAFT -> TEST -> VALIDATE -> STAGING -> CANARY -> PRODUCTION
    v_engine.promote_rule("DET-TEST-01", "TEST")
    v_engine.promote_rule("DET-TEST-01", "VALIDATE")
    v_engine.promote_rule("DET-TEST-01", "STAGING")
    v_engine.promote_rule("DET-TEST-01", "CANARY", canary_assets=["MTA-CANARY"])
    assert v_engine.get_rule("DET-TEST-01").canary_target_assets == ["MTA-CANARY"]
    v_engine.promote_rule("DET-TEST-01", "PRODUCTION")
    assert v_engine.get_rule("DET-TEST-01").status == "PRODUCTION"

    # Illegal jump must raise error
    rule_draft = DetectionRule(detection_id="DET-JUMP", name="Jump", description="", logic={}, status="DRAFT")
    v_engine.register_rule(rule_draft)
    with pytest.raises(ValueError):
        v_engine.promote_rule("DET-JUMP", "PRODUCTION")

    # Create new version with diff and audit
    new_ver = v_engine.create_new_version(
        base_rule_id="DET-TEST-01",
        new_version="1.1",
        updates={"logic": {"threshold": 20}},
        author="analyst-test",
        reason="Tightening threshold"
    )
    assert new_ver.version == "1.1"
    assert len(v_engine.audit_log) == 1
    assert v_engine.audit_log[0].diff["threshold_changes"]["threshold"] == {"from": 10, "to": 20}
