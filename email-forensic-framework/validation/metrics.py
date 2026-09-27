"""
Phase 23 - Detection Validation Metrics.
Calculates TP, FP, TN, FN, Precision, Recall, F1, and Latency for rule evaluation.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class DetectionPerformanceMetrics:
    detection_id: str
    version: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_samples: int = 0
    average_latency_ms: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 3) if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 3) if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * (p * r) / (p + r), 3) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "version": self.version,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1_score,
            "avg_latency_ms": round(self.average_latency_ms, 2)
        }
