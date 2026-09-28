"""
DLP Flow Classifier and Inspection.
Component 29.30: Inspects payload headers, data classifications, and flow metadata for DLP engines.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from data_security.inventory.normalization import ClassificationLevel
from data_security.classification.patterns import SensitiveDataPatterns


class DLPFlowClassifier:
    """Inspects flow streams or export chunks to classify payload content."""

    def classify_payload_snippet(self, text_snippet: str) -> Dict[str, Any]:
        matched = []
        for p in SensitiveDataPatterns.PATTERNS:
            if p.regex.search(text_snippet):
                matched.append(p.category)

        if "CREDENTIALS_AUTH" in matched or "FINANCIAL_PAYMENT" in matched:
            inferred = ClassificationLevel.RESTRICTED
        elif "IDENTITY_CONTACT" in matched:
            inferred = ClassificationLevel.SENSITIVE
        else:
            inferred = ClassificationLevel.INTERNAL

        return {
            "inferred_classification": inferred,
            "detected_categories": list(set(matched)),
            "matches_count": len(matched),
        }
