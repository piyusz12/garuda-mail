"""Tests for Replay, Regression, and Change Impact Dependency Analysis."""
import pytest
from validation.replay import (
    HistoricalValidationReplay,
    ContinuousRegressionEngine,
    ChangeImpactAnalyzer,
)
from validation.range import RangeManager
from validation.scenarios import ScenarioRepository
from validation.execution import ScenarioRunner, KillSwitchManager


def test_change_impact_analyzer():
    analyzer = ChangeImpactAnalyzer()

    # Changing cert parser should affect SCN-102
    affected_cert = analyzer.calculate_affected_scenarios(["cert_parser"])
    assert "SCN-102" in affected_cert

    # Changing TLS sensor should affect SCN-101 and SCN-102
    affected_tls = analyzer.calculate_affected_scenarios(["tls_sensor"])
    assert "SCN-101" in affected_tls
    assert "SCN-102" in affected_tls

    # Changing PQC hybrid kex should affect SCN-104
    affected_pqc = analyzer.calculate_affected_scenarios(["pqc_hybrid_kex"])
    assert "SCN-104" in affected_pqc


def test_historical_validation_replay():
    events = [
        {"event_type": "tls_event", "tls_version": "TLS 1.0", "label": "POSITIVE"},
        {"event_type": "tls_event", "tls_version": "TLS 1.3", "label": "NEGATIVE"},
    ]
    res = HistoricalValidationReplay.replay_corpus("DET-TLS-001", events)
    assert res.total_events_evaluated == 2
    assert res.true_positive_triggers == 1
    assert res.false_positive_triggers == 0
    assert res.is_regression_free is True


def test_continuous_regression_engine():
    mgr = RangeManager()
    runner = ScenarioRunner(range_manager=mgr, kill_switch=KillSwitchManager())
    engine = ContinuousRegressionEngine(runner=runner)

    scn = ScenarioRepository().get("SCN-101")
    reg_result = engine.evaluate_regression(scn, range_id="RANGE-A")
    assert reg_result.scenario_id == "SCN-101"
    assert reg_result.current_outcome == "PASS"
