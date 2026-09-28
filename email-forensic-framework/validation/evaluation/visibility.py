"""
Sensor Coverage & Visibility Evaluator.
Distinguishes visibility gaps (telemetry missing from sensor) from detection gaps.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from validation.adversary.techniques import Technique
from validation.range.environments import RangeEnvironment


@dataclass
class VisibilityEvaluationResult:
    technique_id: str
    target_asset: str
    required_telemetry: List[str]
    observed_telemetry: List[str]
    is_visible: bool
    missing_telemetry: List[str] = field(default_factory=list)
    active_sensors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "target_asset": self.target_asset,
            "required_telemetry": self.required_telemetry,
            "observed_telemetry": self.observed_telemetry,
            "is_visible": self.is_visible,
            "missing_telemetry": self.missing_telemetry,
            "active_sensors": self.active_sensors,
        }


class VisibilityEvaluator:
    """Evaluates whether host and network sensors captured mandatory telemetry."""

    @staticmethod
    def evaluate(
        technique: Technique,
        target_asset: str,
        range_env: RangeEnvironment,
        observed_events: List[str],
    ) -> VisibilityEvaluationResult:
        asset = range_env.get_asset(target_asset)
        installed_sensors = asset.installed_sensors if asset else range_env.sensor_stack

        missing = [t for t in technique.expected_telemetry if t not in observed_events]
        is_visible = len(missing) == 0

        return VisibilityEvaluationResult(
            technique_id=technique.technique_id,
            target_asset=target_asset,
            required_telemetry=technique.expected_telemetry,
            observed_telemetry=observed_events,
            is_visible=is_visible,
            missing_telemetry=missing,
            active_sensors=installed_sensors,
        )
