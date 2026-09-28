"""
Validation Copilot Diagnostic Assistant.
Answers "Why did this validation fail?" with structured root cause analysis and evidence references.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from validation.execution.runner import ValidationRun, ScenarioOutcome


@dataclass
class CopilotDiagnosis:
    run_id: str
    scenario_id: str
    outcome: str
    summary: str
    expected_vs_observed: Dict[str, Any]
    evidence_references: List[str]
    root_cause_layer: str  # SENSOR, DETECTION, SOAR_RESPONSE, VERIFICATION, ENVIRONMENT
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "outcome": self.outcome,
            "summary": self.summary,
            "expected_vs_observed": self.expected_vs_observed,
            "evidence_references": self.evidence_references,
            "root_cause_layer": self.root_cause_layer,
            "recommended_action": self.recommended_action,
        }


class ValidationCopilot:
    """Intelligent diagnostic copilot analyzing validation outcomes."""

    @staticmethod
    def diagnose_failure(run: ValidationRun) -> CopilotDiagnosis:
        outcome = run.outcome.value

        if run.outcome == ScenarioOutcome.PASS:
            return CopilotDiagnosis(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                outcome=outcome,
                summary="Validation completed successfully. All telemetry observed, detections triggered, and responses verified.",
                expected_vs_observed={"status": "All expectations satisfied."},
                evidence_references=[f"Run {run.run_id}", f"Case {run.case_id}"],
                root_cause_layer="NONE",
                recommended_action="Maintain current baseline. Schedule next periodic validation.",
            )

        if run.outcome == ScenarioOutcome.VISIBILITY_GAP:
            return CopilotDiagnosis(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                outcome=outcome,
                summary="Visibility Failure: Emulated adversarial actions failed to generate expected telemetry at the sensor layer.",
                expected_vs_observed={
                    "observed_telemetry": run.telemetry_observed,
                    "gaps": run.gaps_identified,
                },
                evidence_references=[f"Run {run.run_id}", f"Range {run.range_id}", f"Target {run.target_assets}"],
                root_cause_layer="SENSOR",
                recommended_action="Inspect passive network tap and TLS parser version on target assets. Ensure protocol packet capturing is active.",
            )

        if run.outcome == ScenarioOutcome.DETECTION_GAP:
            return CopilotDiagnosis(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                outcome=outcome,
                summary="Detection Failure: Telemetry was observed by sensors, but detection rules or ML models failed to fire alerts.",
                expected_vs_observed={
                    "telemetry_seen": run.telemetry_observed,
                    "detections_fired": run.detections_fired,
                    "gaps": run.gaps_identified,
                },
                evidence_references=[f"Run {run.run_id}", f"Observed events: {len(run.telemetry_observed)}"],
                root_cause_layer="DETECTION",
                recommended_action="Review detection rule logic, threshold parameters, and JA4 rarity baselines in Detection Engineering repository.",
            )

        if run.outcome == ScenarioOutcome.RESPONSE_GAP:
            return CopilotDiagnosis(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                outcome=outcome,
                summary="Response Failure: Incident case was triaged, but the defensive playbook action was either not staged or failed execution.",
                expected_vs_observed={
                    "case_id": run.case_id,
                    "action_staged": run.action_staged,
                    "action_executed": run.action_executed,
                    "gaps": run.gaps_identified,
                },
                evidence_references=[f"Run {run.run_id}", f"Case {run.case_id}"],
                root_cause_layer="SOAR_RESPONSE",
                recommended_action="Check SOAR playbook decision matrices, action adapter connectivity, and approval workflow configurations.",
            )

        if run.outcome == ScenarioOutcome.VERIFICATION_GAP:
            return CopilotDiagnosis(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                outcome=outcome,
                summary="Verification Failure: Response action completed, but post-remediation verification checks failed to confirm secure posture.",
                expected_vs_observed={
                    "verification_passed": run.verification_passed,
                    "gaps": run.gaps_identified,
                },
                evidence_references=[f"Run {run.run_id}", f"Case {run.case_id}"],
                root_cause_layer="VERIFICATION",
                recommended_action="Verify active certificate trust chains, TLS cipher parameters, and host firewall rules.",
            )

        return CopilotDiagnosis(
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            outcome=outcome,
            summary=f"Validation stopped or blocked: {run.stop_reason or 'Preconditions or safety check unmet.'}",
            expected_vs_observed={"stop_reason": run.stop_reason},
            evidence_references=[f"Run {run.run_id}"],
            root_cause_layer="ENVIRONMENT",
            recommended_action="Review range asset availability, operator permissions, and isolation boundaries before re-running.",
        )
