"""AI Configuration Drift Detection.
Component 30.34: Tracks configuration drift across system prompts, tool bindings, and egress permissions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class AIConfigurationDrift:
    drift_id: str
    asset_id: str
    parameter_name: str
    baseline_value: Any
    observed_value: Any
    severity: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "asset_id": self.asset_id,
            "parameter_name": self.parameter_name,
            "baseline_value": self.baseline_value,
            "observed_value": self.observed_value,
            "severity": self.severity,
            "detected_at": self.detected_at,
        }


class AIConfigurationDriftDetector:
    """Detects when an AI agent or model deployment configuration drifts from its approved baseline."""

    def __init__(self):
        self._baselines: Dict[str, Dict[str, Any]] = {}

    def set_baseline(self, asset_id: str, baseline_config: Dict[str, Any]) -> None:
        self._baselines[asset_id] = baseline_config

    def check_drift(self, asset_id: str, current_config: Dict[str, Any]) -> List[AIConfigurationDrift]:
        base = self._baselines.get(asset_id, {})
        drifts = []

        for param, expected_val in base.items():
            actual_val = current_config.get(param)
            if actual_val is not None and actual_val != expected_val:
                sev = "CRITICAL" if param in ("egress_network_allowed", "artifact_hash") else "HIGH"
                drifts.append(
                    AIConfigurationDrift(
                        drift_id=f"AIDRIFT-{asset_id}-{param}",
                        asset_id=asset_id,
                        parameter_name=param,
                        baseline_value=expected_val,
                        observed_value=actual_val,
                        severity=sev,
                    )
                )

        return drifts
