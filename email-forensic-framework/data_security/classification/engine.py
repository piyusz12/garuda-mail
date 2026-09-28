"""
Data Classification Engine.
Components 29.3, 29.4, 29.13: Orchestrates multi-signal classification, confidence scoring, and review triggers.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from data_security.inventory.normalization import DataAsset, ClassificationLevel
from data_security.classification.patterns import SensitiveDataPatterns
from data_security.classification.ml import MLDataClassifier, ClassificationSignal
from data_security.classification.review import ClassificationReviewManager, ClassificationReviewRecord


@dataclass
class ClassificationResult:
    data_asset_id: str
    level: ClassificationLevel
    confidence: float
    detected_categories: List[str]
    signals: List[str]
    needs_human_review: bool
    classified_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data_asset_id": self.data_asset_id,
            "level": self.level.value if isinstance(self.level, ClassificationLevel) else self.level,
            "confidence": round(self.confidence, 3),
            "detected_categories": self.detected_categories,
            "signals": self.signals,
            "needs_human_review": self.needs_human_review,
            "classified_at": self.classified_at,
        }


class DataClassificationEngine:
    """Classifies datasets using schema heuristics, pattern detection, and confidence estimation."""

    def __init__(self, review_manager: Optional[ClassificationReviewManager] = None):
        self.ml_classifier = MLDataClassifier()
        self.review_manager = review_manager or ClassificationReviewManager()
        self.confidence_threshold = 0.85

    def classify_asset(
        self,
        asset: DataAsset,
        sample_payload: Optional[List[Dict[str, Any]]] = None,
    ) -> ClassificationResult:
        all_signals: List[ClassificationSignal] = []
        columns = asset.schema_metadata.get("columns", [])

        # 1. Evaluate columns if available
        for col in columns:
            col_name = col.get("name", "")
            samples = [str(row.get(col_name, "")) for row in (sample_payload or []) if col_name in row]
            signals = self.ml_classifier.evaluate_column(col_name, samples)
            all_signals.extend(signals)

        # 2. Also evaluate asset name
        asset_signals = self.ml_classifier.evaluate_column(asset.name)
        all_signals.extend(asset_signals)

        # 3. Aggregate categories and confidence
        categories = list(set(s.category for s in all_signals))
        conf = max([s.confidence for s in all_signals], default=0.50)

        # Map categories to ClassificationLevel
        if any(c in ["FINANCIAL_PAYMENT", "CREDENTIALS_AUTH", "HEALTH_MEDICAL"] for c in categories):
            level = ClassificationLevel.RESTRICTED
        elif any(c in ["IDENTITY_CONTACT", "IDENTITY_GOVERNMENT"] for c in categories):
            level = ClassificationLevel.SENSITIVE
        elif "Forensic" in asset.name or "Lake" in asset.name:
            level = ClassificationLevel.CONFIDENTIAL
        else:
            level = ClassificationLevel.INTERNAL

        signal_descs = [f"{s.source}: {s.category} ({s.confidence:.2f})" for s in all_signals]
        needs_review = conf < self.confidence_threshold

        result = ClassificationResult(
            data_asset_id=asset.data_asset_id,
            level=level,
            confidence=conf,
            detected_categories=categories,
            signals=signal_descs,
            needs_human_review=needs_review,
        )

        if needs_review:
            self.review_manager.create_review_request(
                data_asset_id=asset.data_asset_id,
                proposed_level=level,
                confidence=conf,
                signals=signal_descs,
            )

        # Update asset sensitivity and classification
        asset.classification = level
        asset.sensitivity_score = 95.0 if level == ClassificationLevel.RESTRICTED else (75.0 if level == ClassificationLevel.SENSITIVE else 40.0)

        return result
