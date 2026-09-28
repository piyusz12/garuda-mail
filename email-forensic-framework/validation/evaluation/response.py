"""
Response Workflow & Control Effectiveness Evaluator.
Validates case triage, automated decisions, playbook selection, and approval routing.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ResponseEvaluationResult:
    case_created: bool
    expected_action: Optional[str]
    actual_action: Optional[str]
    approval_required: bool
    approval_requested: bool
    is_response_adequate: bool
    gap_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_created": self.case_created,
            "expected_action": self.expected_action,
            "actual_action": self.actual_action,
            "approval_required": self.approval_required,
            "approval_requested": self.approval_requested,
            "is_response_adequate": self.is_response_adequate,
            "gap_reason": self.gap_reason,
        }


class ResponseEvaluator:
    """Evaluates whether the SOAR / Incident Response workflow took the required actions."""

    @staticmethod
    def evaluate(
        expected_action: Optional[str],
        actual_action: Optional[str],
        case_created: bool,
        approval_required: bool,
        approval_requested: bool,
    ) -> ResponseEvaluationResult:
        if not expected_action:
            return ResponseEvaluationResult(
                case_created=case_created,
                expected_action=None,
                actual_action=actual_action,
                approval_required=approval_required,
                approval_requested=approval_requested,
                is_response_adequate=True,
            )

        if not case_created:
            return ResponseEvaluationResult(
                case_created=False,
                expected_action=expected_action,
                actual_action=actual_action,
                approval_required=approval_required,
                approval_requested=approval_requested,
                is_response_adequate=False,
                gap_reason="Case was not created upon alert ingestion.",
            )

        if expected_action != actual_action:
            return ResponseEvaluationResult(
                case_created=True,
                expected_action=expected_action,
                actual_action=actual_action,
                approval_required=approval_required,
                approval_requested=approval_requested,
                is_response_adequate=False,
                gap_reason=f"Expected action '{expected_action}', but '{actual_action}' was staged.",
            )

        if approval_required and not approval_requested:
            return ResponseEvaluationResult(
                case_created=True,
                expected_action=expected_action,
                actual_action=actual_action,
                approval_required=approval_required,
                approval_requested=False,
                is_response_adequate=False,
                gap_reason="Playbook requires human approval tier, but no approval request was dispatched.",
            )

        return ResponseEvaluationResult(
            case_created=True,
            expected_action=expected_action,
            actual_action=actual_action,
            approval_required=approval_required,
            approval_requested=approval_requested,
            is_response_adequate=True,
        )
