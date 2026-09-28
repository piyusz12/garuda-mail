"""
Remediation Verification & Retest Engine.
Automates re-validation of defensive gaps and ensures gaps are closed only when tests succeed.
"""
from typing import Dict, List, Optional, Any
from validation.scenarios.builder import ValidationScenario
from validation.execution.runner import ScenarioRunner, ValidationRun, ScenarioOutcome
from .manager import GapManager, ValidationGap, GapStatus


class RemediationRetester:
    """Executes verification re-tests to prove gap resolution."""

    def __init__(self, gap_manager: GapManager, runner: ScenarioRunner):
        self.gap_manager = gap_manager
        self.runner = runner

    def retest_gap(
        self,
        gap_id: str,
        scenario: ValidationScenario,
        range_id: str,
        operator_role: str = "Scenario Operator",
    ) -> Dict[str, Any]:
        gap = self.gap_manager.get_gap(gap_id)
        if not gap:
            raise ValueError(f"Gap {gap_id} not found.")

        # Execute scenario
        run_record: ValidationRun = self.runner.run(
            scenario=scenario,
            range_id=range_id,
            operator_role=operator_role,
        )

        if run_record.outcome == ScenarioOutcome.PASS:
            updated_gap = self.gap_manager.close_gap_on_verified_retest(gap_id, run_record.run_id)
            return {
                "gap_id": gap_id,
                "retest_status": "PASSED",
                "gap_status": updated_gap.status.value,
                "run_id": run_record.run_id,
                "message": "Gap successfully resolved and verified via automated re-test.",
            }
        else:
            updated_gap = self.gap_manager.reopen_gap_on_failed_retest(
                gap_id,
                run_record.run_id,
                reason=f"Scenario finished with outcome {run_record.outcome.value}",
            )
            return {
                "gap_id": gap_id,
                "retest_status": "FAILED",
                "gap_status": updated_gap.status.value,
                "run_id": run_record.run_id,
                "message": f"Retest failed ({run_record.outcome.value}). Gap reopened.",
            }
