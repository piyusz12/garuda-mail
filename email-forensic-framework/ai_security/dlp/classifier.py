"""AI Data Flow Classifier for DLP Contexts.
Component 30.14: Correlates data assets, prompts, and tool arguments to determine composite sensitivity.
"""
from typing import Dict, Any
from data_security.inventory.normalization import ClassificationLevel


class AIDLPClassifier:
    """Classifies AI transfer events based on source assets, prompts, and tool payloads."""

    @classmethod
    def resolve_flow_classification(cls, flow_context: Dict[str, Any]) -> ClassificationLevel:
        asset_class = flow_context.get("asset_classification")
        if asset_class:
            if isinstance(asset_class, ClassificationLevel):
                return asset_class
            return ClassificationLevel(str(asset_class).upper())

        payload = str(flow_context.get("payload", "")).lower()
        if "payment_token" in payload or "private_key" in payload:
            return ClassificationLevel.RESTRICTED
        elif "email" in payload or "phone" in payload:
            return ClassificationLevel.CONFIDENTIAL
        elif "internal" in payload:
            return ClassificationLevel.INTERNAL

        return ClassificationLevel.PUBLIC
