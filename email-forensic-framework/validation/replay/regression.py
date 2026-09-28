"""
Continuous Regression Testing & Environment Drift Validator.
Detects degradation in detection accuracy or response efficiency over time.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from validation.scenarios.builder import ValidationScenario
from validation.execution.runner import ScenarioRunner, ValidationRun, ScenarioOutcome


@dataclass
class RegressionRunResult:
    scenario_id: str
    previous_outcome: str
    current_outcome: str
    is_regression: bool
    latency_delta_ttd_seconds: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "previous_outcome": self.previous_outcome,
            "current_outcome": self.current_outcome,
            "is_regression": self.is_regression,
            "latency_delta_ttd_seconds": round(self.latency_delta_ttd_seconds, 3),
            "description": self.description,
        }


class ContinuousRegressionEngine:
    """Monitors scenario passes and flags sudden regressions when platform components change."""

    def __init__(self, runner: ScenarioRunner):
        self.runner = runner
        self._baseline_results: Dict[str, ValidationRun] = {}

    def set_baseline(self, run: ValidationRun) -> None:
        self._baseline_results[run.scenario_id] = run

    def evaluate_regression(self, scenario: ValidationScenario, range_id: str) -> RegressionRunResult:
        baseline = self._baseline_results.get(scenario.scenario_id)
        current = self.runner.run(scenario, range_id=range_id)

        prev_outcome = baseline.outcome.value if baseline else "UNKNOWN"
        curr_outcome = current.outcome.value

        prev_ttd = baseline.ttd_seconds if (baseline and baseline.ttd_seconds) else 0.0
        curr_ttd = current.ttd_seconds or 0.0
        ttd_delta = curr_ttd - prev_ttd

        # Regression: previously passed, now failed or has gaps
        is_reg = False
        if prev_outcome == ScenarioOutcome.PASS.value and curr_outcome != ScenarioOutcome.PASS.value:
            is_reg = True
            desc = f"REGRESSION DETECTED: Scenario previously passed, but now yielded {curr_outcome}."
        elif is_reg:
            desc = f"REGRESSION: {curr_outcome}"
        else:
            desc = f"No functional regression. Current outcome: {curr_outcome}."

        return RegressionRunResult(
            scenario_id=scenario.scenario_id,
            previous_outcome=prev_outcome,
            current_outcome=curr_outcome,
            is_regression=is_reg,
            latency_delta_ttd_seconds=ttd_delta,
            description=desc,
        )
