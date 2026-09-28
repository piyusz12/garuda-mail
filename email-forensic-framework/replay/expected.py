"""
Phase 23 - Scenario Verification.
Compares replay outcomes with expected detections to report platform coverage and regression.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any
from .scenarios import AttackScenario
from .runner import ReplayExecutionResult

@dataclass
class ScenarioVerificationReport:
    scenario_id: str
    passed: bool
    expected_detections: List[str]
    actual_detections: List[str]
    missing_detections: List[str]
    unexpected_detections: List[str]
    details: str

class ScenarioVerifier:
    """Verifies that an attack scenario produces all expected detection alerts."""

    @classmethod
    def verify(cls, scenario: AttackScenario, result: ReplayExecutionResult) -> ScenarioVerificationReport:
        expected_set = set(scenario.expected_detections)
        actual_set = set(result.triggered_detection_ids)

        missing = list(expected_set - actual_set)
        unexpected = list(actual_set - expected_set)
        passed = len(missing) == 0

        details = "All expected detections fired successfully." if passed else f"DETECTION GAP: Missed {missing}!"

        return ScenarioVerificationReport(
            scenario_id=scenario.scenario_id,
            passed=passed,
            expected_detections=scenario.expected_detections,
            actual_detections=result.triggered_detection_ids,
            missing_detections=missing,
            unexpected_detections=unexpected,
            details=details
        )
