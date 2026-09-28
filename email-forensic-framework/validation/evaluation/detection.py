"""
Detection Coverage & Redundancy Evaluator.
Validates detector activations and measures single-point-of-detection failures.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from validation.adversary.techniques import Technique


@dataclass
class DetectionEvaluationResult:
    technique_id: str
    target_asset: str
    expected_detectors: List[str]
    observed_detectors: List[str]
    is_detected: bool
    missing_detectors: List[str]
    is_resilient: bool  # True if redundant detector caught it (>1 detector)
    redundancy_level: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "target_asset": self.target_asset,
            "expected_detectors": self.expected_detectors,
            "observed_detectors": self.observed_detectors,
            "is_detected": self.is_detected,
            "missing_detectors": self.missing_detectors,
            "is_resilient": self.is_resilient,
            "redundancy_level": self.redundancy_level,
        }


class DetectionEvaluator:
    """Evaluates detection coverage and multi-layer redundancy."""

    @staticmethod
    def evaluate(
        technique: Technique,
        target_asset: str,
        fired_detections: List[str],
    ) -> DetectionEvaluationResult:
        expected = technique.expected_detections
        missing = [d for d in expected if d not in fired_detections]
        is_detected = any(d in fired_detections for d in expected) or len(fired_detections) > 0
        redundancy = len(fired_detections)
        is_resilient = redundancy >= 2

        return DetectionEvaluationResult(
            technique_id=technique.technique_id,
            target_asset=target_asset,
            expected_detectors=expected,
            observed_detectors=fired_detections,
            is_detected=is_detected,
            missing_detectors=missing,
            is_resilient=is_resilient,
            redundancy_level=redundancy,
        )
