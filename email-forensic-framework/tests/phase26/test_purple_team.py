"""Tests for Purple Team Collaborative Engine, Coverage Matrix, and Gap Identification."""
import pytest
from validation.range import RangeManager
from validation.scenarios import ScenarioRepository
from validation.execution import ScenarioRunner, KillSwitchManager
from validation.purple_team import (
    PurpleTeamComparator,
    CoverageMatrix,
    PurpleTeamEngine,
)


def test_purple_team_comparator():
    delta_covered = PurpleTeamComparator.compare_step(
        technique_id="TECH-042",
        target_asset="MTA-07",
        emitted_behavior={"tls_version": "TLS 1.0"},
        observed_telemetry=["tls_event", "ja4_event"],
        fired_detections=["TLS-LEGACY-001"],
        case_created=True,
        action_executed=True,
        verification_passed=True,
    )
    assert delta_covered.is_fully_covered is True
    assert delta_covered.gap_summary == "Fully Covered"

    # Missing detection delta
    delta_gap = PurpleTeamComparator.compare_step(
        technique_id="TECH-042",
        target_asset="MTA-07",
        emitted_behavior={"tls_version": "TLS 1.0"},
        observed_telemetry=["tls_event"],
        fired_detections=[],
        case_created=False,
        action_executed=False,
        verification_passed=False,
    )
    assert delta_gap.is_fully_covered is False
    assert "Detection Gap" in delta_gap.gap_summary


def test_coverage_matrix():
    matrix = CoverageMatrix()
    matrix.record("TECH-A", "MTA-01", visibility=True, detection=True, response=True)
    matrix.record("TECH-B", "MTA-01", visibility=True, detection=True, response=False)
    matrix.record("TECH-C", "MTA-01", visibility=True, detection=False, response=False)
    matrix.record("TECH-D", "MTA-01", visibility=False, detection=False, response=False)

    summary = matrix.get_summary()
    assert summary["total_evaluations"] == 4
    assert summary["visibility_coverage_pct"] == 75.0
    assert summary["detection_coverage_pct"] == 50.0
    assert summary["response_coverage_pct"] == 25.0
    assert summary["full_coverage_pct"] == 25.0


def test_purple_team_engine_exercise():
    range_mgr = RangeManager()
    runner = ScenarioRunner(range_manager=range_mgr, kill_switch=KillSwitchManager())
    engine = PurpleTeamEngine(runner=runner)

    scn = ScenarioRepository().get("SCN-101")
    res = engine.execute_exercise(scn, range_id="RANGE-A")

    assert res.run_outcome in ("PASS", "PARTIAL_PASS")
    assert len(res.deltas) == 1
    assert res.deltas[0].telemetry_observed is True
    assert res.deltas[0].detection_observed is True
