"""
Statistical and Heuristic Content Classifier.
Component 29.3 & 29.4: Simulates ML-assisted classification over sampled content and column metadata.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from data_security.classification.patterns import SensitiveDataPatterns


@dataclass
class ClassificationSignal:
    source: str  # "SCHEMA_NAME", "REGEX_PATTERN", "ENTROPY_ANALYSIS"
    category: str
    confidence: float
    matched_fragment: Optional[str] = None


class MLDataClassifier:
    """Combines entropy analysis, statistical distributions, and pattern weights."""

    def evaluate_column(self, column_name: str, sample_values: Optional[List[str]] = None) -> List[ClassificationSignal]:
        signals: List[ClassificationSignal] = []
        c_lower = column_name.lower().strip()

        # 1. Schema Name Signal
        for key, (cat, conf) in SensitiveDataPatterns.COLUMN_NAME_SIGNALS.items():
            if key in c_lower:
                signals.append(
                    ClassificationSignal(
                        source="SCHEMA_NAME",
                        category=cat,
                        confidence=conf,
                        matched_fragment=key,
                    )
                )

        # 2. Content Sampling Signals
        if sample_values:
            for val in sample_values[:20]:  # Limit sample size
                for p in SensitiveDataPatterns.PATTERNS:
                    if p.regex.search(str(val)):
                        signals.append(
                            ClassificationSignal(
                                source="REGEX_PATTERN",
                                category=p.category,
                                confidence=p.confidence_weight,
                                matched_fragment=f"Sample matched {p.pattern_name}",
                            )
                        )
                        break

        return signals
