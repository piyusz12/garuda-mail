"""
Data Posture Drift Tracking.
Component 29.13: Detects configuration and exposure drift on data assets.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class DataPostureDrift:
    drift_id: str
    asset_id: str
    attribute: str
    approved_state: Any
    observed_state: Any
    severity: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "asset_id": self.asset_id,
            "attribute": self.attribute,
            "approved_state": self.approved_state,
            "observed_state": self.observed_state,
            "severity": self.severity,
            "detected_at": self.detected_at,
        }


class DataPostureDriftDetector:
    """Tracks baseline posture state and raises alerts when settings drift out of policy."""

    def __init__(self):
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._drifts: List[DataPostureDrift] = []

    def set_baseline(self, asset_id: str, baseline_config: Dict[str, Any]) -> None:
        self._baselines[asset_id] = baseline_config

    def check_drift(self, asset_id: str, current_config: Dict[str, Any]) -> List[DataPostureDrift]:
        base = self._baselines.get(asset_id, {})
        new_drifts = []

        for k, v in base.items():
            curr_v = current_config.get(k)
            if curr_v is not None and curr_v != v:
                drift = DataPostureDrift(
                    drift_id=f"DDRIFT-{asset_id}-{k}",
                    asset_id=asset_id,
                    attribute=k,
                    approved_state=v,
                    observed_state=curr_v,
                    severity="CRITICAL" if k in ("is_publicly_exposed", "encryption_at_rest") else "HIGH",
                )
                new_drifts.append(drift)
                self._drifts.append(drift)

        return new_drifts

    def list_drifts(self) -> List[DataPostureDrift]:
        return list(self._drifts)
