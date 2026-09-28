"""
Response Verification and Recovery Posture Evaluator.
Validates that actions not only completed, but restored the system to an authorized, resilient posture.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class VerificationEvaluationResult:
    is_verified: bool
    expected_criteria: Dict[str, Any]
    observed_telemetry: Dict[str, Any]
    failed_checks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_verified": self.is_verified,
            "expected_criteria": self.expected_criteria,
            "observed_telemetry": self.observed_telemetry,
            "failed_checks": self.failed_checks,
        }


class VerificationEvaluator:
    """Checks whether the defensive response produced the verified steady-state."""

    @staticmethod
    def evaluate(
        expected_criteria: Dict[str, Any],
        observed_telemetry: Dict[str, Any],
    ) -> VerificationEvaluationResult:
        failed = []
        for key, expected_val in expected_criteria.items():
            if key not in observed_telemetry:
                failed.append(f"Missing verification metric: {key}")
            elif observed_telemetry[key] != expected_val:
                failed.append(f"Metric '{key}' mismatch: expected {expected_val}, got {observed_telemetry[key]}")

        is_verified = len(failed) == 0

        return VerificationEvaluationResult(
            is_verified=is_verified,
            expected_criteria=expected_criteria,
            observed_telemetry=observed_telemetry,
            failed_checks=failed,
        )
