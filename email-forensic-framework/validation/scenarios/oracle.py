"""
Scenario Oracle and Ground Truth Specification.
Defines deterministic expectations for telemetry, detection rules, SOC cases, response actions, and verification.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ScenarioOracle:
    """The Oracle defines what *should* happen when this scenario runs."""
    expected_telemetry: List[str]
    expected_detections: List[str]
    expected_case_created: bool = True
    expected_response_action: Optional[str] = None
    expected_approval_required: bool = False
    expected_verification_criteria: Dict[str, Any] = field(default_factory=dict)
    acceptable_ttd_seconds: float = 30.0  # Max acceptable time-to-detect
    acceptable_ttr_seconds: float = 60.0  # Max acceptable time-to-respond

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expected_telemetry": self.expected_telemetry,
            "expected_detections": self.expected_detections,
            "expected_case_created": self.expected_case_created,
            "expected_response_action": self.expected_response_action,
            "expected_approval_required": self.expected_approval_required,
            "expected_verification_criteria": self.expected_verification_criteria,
            "acceptable_ttd_seconds": self.acceptable_ttd_seconds,
            "acceptable_ttr_seconds": self.acceptable_ttr_seconds,
        }


@dataclass
class GroundTruth:
    """Historical and definitive ground truth log for a validation run."""
    scenario_id: str
    run_id: str
    target_asset: str
    executed_techniques: List[str]
    injected_events: List[Dict[str, Any]]
    start_time: float
    end_time: Optional[float] = None
    stopping_condition_met: bool = False
    stop_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "target_asset": self.target_asset,
            "executed_techniques": self.executed_techniques,
            "injected_events_count": len(self.injected_events),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "stopping_condition_met": self.stopping_condition_met,
            "stop_reason": self.stop_reason,
        }
