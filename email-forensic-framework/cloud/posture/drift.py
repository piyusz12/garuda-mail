"""
Cloud Configuration Drift Detection.
Component 43: Compares desired/approved IaC state against actual live observed cloud state.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class ConfigurationDrift:
    drift_id: str
    resource_id: str
    attribute: str = "configuration"
    approved_value: Any = None
    observed_value: Any = None
    drift_type: Optional[str] = None
    expected_state: Any = None
    actual_state: Any = None
    severity: Any = "HIGH"
    detected_by: str = "CloudDriftDetector"
    detected_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.drift_type and not self.attribute:
            self.attribute = self.drift_type
        if self.expected_state is not None and self.approved_value is None:
            self.approved_value = self.expected_state
        if self.actual_state is not None and self.observed_value is None:
            self.observed_value = self.actual_state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "resource_id": self.resource_id,
            "attribute": self.attribute,
            "approved_value": self.approved_value,
            "observed_value": self.observed_value,
            "severity": str(self.severity),
            "detected_by": self.detected_by,
            "detected_at": self.detected_at,
        }


class CloudDriftDetector:
    """Detects discrepancies between approved IaC declarations and live running state."""

    def __init__(self):
        # resource_id -> baseline configuration dict
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._recorded_drifts: Dict[str, ConfigurationDrift] = {}

    def set_approved_baseline(self, resource_id: str, baseline_config: Dict[str, Any]) -> None:
        self._baselines[resource_id] = baseline_config

    def record_drift(self, drift: ConfigurationDrift) -> None:
        self._recorded_drifts[drift.drift_id] = drift

    def get_drift(self, drift_id: str) -> Optional[ConfigurationDrift]:
        return self._recorded_drifts.get(drift_id)

    def list_drifts(self) -> List[ConfigurationDrift]:
        return list(self._recorded_drifts.values())

    def detect_drift(self, resource_id: str, live_config: Dict[str, Any]) -> List[ConfigurationDrift]:
        baseline = self._baselines.get(resource_id)
        if not baseline:
            return []

        drifts = []
        for attr, exp_val in baseline.items():
            obs_val = live_config.get(attr)
            if obs_val != exp_val:
                drift = ConfigurationDrift(
                    drift_id=f"DRIFT-{resource_id}-{attr}",
                    resource_id=resource_id,
                    attribute=attr,
                    approved_value=exp_val,
                    observed_value=obs_val,
                    severity="CRITICAL" if attr in ("is_internet_facing", "encryption_enabled") else "HIGH",
                )
                drifts.append(drift)
                self.record_drift(drift)
        return drifts
