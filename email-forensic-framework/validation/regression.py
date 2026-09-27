"""
Phase 23 - Detection Regression Testing Engine.
Validates new rule versions against golden corpora to prevent detection regressions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import time

from .datasets import ValidationDatasetRepository, LabeledEvent
from .metrics import DetectionPerformanceMetrics
from detection.evaluator import DetectionEvaluator

@dataclass
class RegressionComparison:
    rule_id: str
    base_version: str
    new_version: str
    base_metrics: DetectionPerformanceMetrics
    new_metrics: DetectionPerformanceMetrics
    regression_detected: bool
    reasons: List[str] = field(default_factory=list)


class DetectionRegressionTester:
    """Executes regression suites comparing new rule revisions to previous baselines."""

    @classmethod
    def test_version_regression(cls, base_rule: Any, new_rule: Any, dataset: Optional[List[LabeledEvent]] = None) -> RegressionComparison:
        dataset = dataset or ValidationDatasetRepository.get_tls_test_dataset()

        base_metrics = cls._evaluate_rule_against_dataset(base_rule, dataset)
        new_metrics = cls._evaluate_rule_against_dataset(new_rule, dataset)

        reasons = []
        is_regression = False

        if new_metrics.precision < base_metrics.precision:
            reasons.append(f"Precision dropped from {base_metrics.precision} to {new_metrics.precision}")
            is_regression = True

        if new_metrics.recall < base_metrics.recall:
            reasons.append(f"Recall dropped from {base_metrics.recall} to {new_metrics.recall} (missed previously caught true positives)")
            is_regression = True

        if new_metrics.false_positives > base_metrics.false_positives:
            reasons.append(f"New false positives introduced (+{new_metrics.false_positives - base_metrics.false_positives})")
            is_regression = True

        return RegressionComparison(
            rule_id=getattr(base_rule, "detection_id", "DET-UNKNOWN"),
            base_version=getattr(base_rule, "version", "1.0"),
            new_version=getattr(new_rule, "version", "1.1"),
            base_metrics=base_metrics,
            new_metrics=new_metrics,
            regression_detected=is_regression,
            reasons=reasons
        )

    @classmethod
    def _evaluate_rule_against_dataset(cls, rule: Any, dataset: List[LabeledEvent]) -> DetectionPerformanceMetrics:
        metrics = DetectionPerformanceMetrics(
            detection_id=getattr(rule, "detection_id", "DET-UNKNOWN"),
            version=getattr(rule, "version", "1.0"),
            total_samples=len(dataset)
        )
        total_time = 0.0

        for event in dataset:
            t0 = time.perf_counter()
            matched, _ = DetectionEvaluator.evaluate(
                rule_type=getattr(rule, "rule_type", "SIGNATURE"),
                logic=getattr(rule, "logic", {}),
                event_data=event.data,
                context={}
            )
            total_time += (time.perf_counter() - t0) * 1000.0

            is_positive = event.label in ("POSITIVE", "EDGE_CASE")
            if matched and is_positive:
                metrics.true_positives += 1
            elif matched and not is_positive:
                metrics.false_positives += 1
            elif not matched and is_positive:
                metrics.false_negatives += 1
            elif not matched and not is_positive:
                metrics.true_negatives += 1

        metrics.average_latency_ms = total_time / max(1, len(dataset))
        return metrics
