"""
Tests for Phase 23 Attack Replay Framework and Scenario Verification.
"""
import pytest
from replay.scenarios import get_scenario_007
from replay.runner import AttackReplayRunner
from replay.expected import ScenarioVerifier
from detection.models import DetectionRule
from detection.engine import DetectionEngine
from detection.correlation import CorrelationEngine, SequenceDefinition, TemporalStage

def test_attack_replay_scenario_007():
    scenario = get_scenario_007()
    assert scenario.scenario_id == "SCENARIO-007"
    assert len(scenario.events) == 4

    # Setup engine with matching detection rule
    corr = CorrelationEngine()
    engine = DetectionEngine(correlation=corr)
    rule1 = DetectionRule(
        detection_id="DET-TLS-001",
        name="Legacy TLS",
        description="",
        rule_type="SIGNATURE",
        logic={"conditions": [{"field": "tls_version", "op": "IN", "value": ["TLS 1.0", "TLS 1.1"]}]},
        status="PRODUCTION"
    )
    rule2 = DetectionRule(
        detection_id="DET-221",
        name="Rare JA4",
        description="",
        rule_type="ANOMALY",
        logic={"rarity_field": "ja4_rarity", "max_rarity": 0.05},
        status="PRODUCTION"
    )
    engine.register_rule(rule1)
    engine.register_rule(rule2)

    # Replay scenario
    result = AttackReplayRunner.replay_scenario(scenario, engine)
    assert result.total_events_replayed == 4
    assert "DET-TLS-001" in result.triggered_detection_ids
    assert "DET-221" in result.triggered_detection_ids

    # Verify expected outcomes
    verif = ScenarioVerifier.verify(scenario, result)
    assert verif.passed is True
    assert len(verif.missing_detections) == 0
