"""
Phase 25 — Detection & Model Drift Tracking
Monitors decay in detection precision and statistical distribution shifts in AI features / JA4 fingerprints.
"""

from typing import Dict, List, Optional, Any
import time


class DetectionDriftTracker:
    """Detects when a detection rule becomes noisy or degrades in precision over time."""

    DRIFT_FPR_THRESHOLD = 0.20  # 20% False Positive Rate threshold

    @classmethod
    def evaluate_drift(cls, detection_id: str, historical_monthly_fpr: List[float]) -> Dict[str, Any]:
        """
        Evaluates drift across monthly false-positive observations.
        e.g., [0.03, 0.07, 0.18, 0.31] -> DETECTION_DRIFT
        """
        if not historical_monthly_fpr:
            return {"detection_id": detection_id, "has_drift": False, "status": "STABLE"}

        latest_fpr = historical_monthly_fpr[-1]
        is_increasing = len(historical_monthly_fpr) >= 2 and historical_monthly_fpr[-1] > historical_monthly_fpr[0]
        has_drift = latest_fpr >= cls.DRIFT_FPR_THRESHOLD or (is_increasing and (latest_fpr - historical_monthly_fpr[0]) > 0.15)

        return {
            "detection_id": detection_id,
            "has_drift": has_drift,
            "current_fpr": round(latest_fpr, 4),
            "historical_trend": historical_monthly_fpr,
            "status": "DETECTION_DRIFT" if has_drift else "STABLE",
            "action_required": "TUNE_DETECTION_RULE" if has_drift else "NONE",
        }


class ModelDriftTracker:
    """Detects shifts in feature and JA4 fingerprint distributions for AI anomaly models."""

    DRIFT_SHIFT_THRESHOLD = 0.30  # 30% shift threshold

    @classmethod
    def evaluate_feature_drift(
        cls,
        model_id: str,
        baseline_distribution: Dict[str, float],
        observed_distribution: Dict[str, float],
    ) -> Dict[str, Any]:
        """Calculates total variation distance between baseline and observed feature distributions."""
        all_keys = set(baseline_distribution.keys()).union(observed_distribution.keys())
        total_shift = 0.0

        for k in all_keys:
            p = baseline_distribution.get(k, 0.0)
            q = observed_distribution.get(k, 0.0)
            total_shift += abs(p - q)

        total_shift = min(1.0, total_shift / 2.0)
        has_drift = total_shift >= cls.DRIFT_SHIFT_THRESHOLD

        return {
            "model_id": model_id,
            "has_drift": has_drift,
            "distribution_shift": round(total_shift, 4),
            "status": "MODEL_REVIEW_REQUIRED" if has_drift else "HEALTHY",
            "action_required": "RETRAIN_AI_MODEL" if has_drift else "NONE",
        }
