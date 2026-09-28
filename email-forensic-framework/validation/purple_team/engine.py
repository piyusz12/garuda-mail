"""
Purple Team Engine & Collaborative Validation Loop.
Coordinates red emulation and blue detection validation into a unified feedback cycle.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from validation.adversary.techniques import Technique, TechniqueLibrary
from validation.scenarios.builder import ValidationScenario
from validation.execution.runner import ScenarioRunner, ValidationRun
from .comparison import PurpleTeamComparator, ComparisonDelta
from .coverage import CoverageMatrix


@dataclass
class PurpleTeamExerciseResult:
    scenario_id: str
    run_id: str
    target_assets: List[str]
    deltas: List[ComparisonDelta]
    coverage_summary: Dict[str, Any]
    run_outcome: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "target_assets": self.target_assets,
            "deltas": [d.to_dict() for d in self.deltas],
            "coverage_summary": self.coverage_summary,
            "run_outcome": self.run_outcome,
            "timestamp": self.timestamp,
        }


class PurpleTeamEngine:
    """Orchestrates purple team validation loops, updating coverage and generating comparison deltas."""

    def __init__(self, runner: ScenarioRunner, technique_library: Optional[TechniqueLibrary] = None):
        self.runner = runner
        self.technique_library = technique_library or TechniqueLibrary()
        self.coverage_matrix = CoverageMatrix()
        self.history: List[PurpleTeamExerciseResult] = []

    def execute_exercise(
        self,
        scenario: ValidationScenario,
        range_id: str,
        simulate_detection_gap: bool = False,
        simulate_visibility_gap: bool = False,
        simulate_response_gap: bool = False,
    ) -> PurpleTeamExerciseResult:
        run_record: ValidationRun = self.runner.run(
            scenario=scenario,
            range_id=range_id,
            simulate_detection_gap=simulate_detection_gap,
            simulate_visibility_gap=simulate_visibility_gap,
            simulate_response_gap=simulate_response_gap,
        )

        deltas = []
        target = scenario.target_assets[0] if scenario.target_assets else "MTA-07"

        for step in scenario.steps:
            tech = self.technique_library.get(step.technique_id)
            delta = PurpleTeamComparator.compare_step(
                technique_id=step.technique_id,
                target_asset=target,
                emitted_behavior=step.parameters,
                observed_telemetry=run_record.telemetry_observed,
                fired_detections=run_record.detections_fired,
                case_created=run_record.case_id is not None,
                action_executed=run_record.action_executed,
                verification_passed=run_record.verification_passed,
            )
            deltas.append(delta)

            # Update master coverage matrix
            self.coverage_matrix.record(
                technique_id=step.technique_id,
                asset_id=target,
                visibility=delta.telemetry_observed,
                detection=delta.detection_observed,
                response=delta.response_observed,
            )

        result = PurpleTeamExerciseResult(
            scenario_id=scenario.scenario_id,
            run_id=run_record.run_id,
            target_assets=scenario.target_assets,
            deltas=deltas,
            coverage_summary=self.coverage_matrix.get_summary(),
            run_outcome=run_record.outcome.value,
        )
        self.history.append(result)
        return result
