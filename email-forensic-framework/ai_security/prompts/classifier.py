"""Prompt Classification and Sensitivity Inspection.
Components 30.10, 30.14, 30.23: Analyzes prompt input for data classification levels and intent.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import re
import time

from data_security.inventory.normalization import ClassificationLevel


@dataclass
class PromptInspectionResult:
    prompt_id: str
    classification: ClassificationLevel
    sensitivity_score: float
    detected_entities: List[str]
    intent_category: str
    has_pii: bool
    has_secrets: bool
    is_safe: bool
    details: str
    inspected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_id": self.prompt_id,
            "classification": self.classification.value,
            "sensitivity_score": self.sensitivity_score,
            "detected_entities": self.detected_entities,
            "intent_category": self.intent_category,
            "has_pii": self.has_pii,
            "has_secrets": self.has_secrets,
            "is_safe": self.is_safe,
            "details": self.details,
            "inspected_at": self.inspected_at,
        }


class PromptClassifier:
    """Classifies user and agent prompts into sensitivity tiers (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)."""

    SECRET_PATTERNS = [
        re.compile(r"(?:api_key|access_token|secret_key|private_key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,}['\"]?", re.IGNORECASE),
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ]

    PII_PATTERNS = [
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,15}\b"),
        re.compile(r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b"),
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    ]

    def classify_prompt(self, prompt_text: str, caller_id: str = "USER-1192") -> PromptInspectionResult:
        detected_entities = []
        has_secrets = False
        has_pii = False

        # Secret detection
        for p in self.SECRET_PATTERNS:
            if p.search(prompt_text):
                has_secrets = True
                detected_entities.append("CREDENTIAL_SECRET")
                break

        # PII detection
        for p in self.PII_PATTERNS:
            if p.search(prompt_text):
                has_pii = True
                detected_entities.append("CUSTOMER_PII")
                break

        # Determine classification
        if has_secrets or "payment_token" in prompt_text.lower() or "credit_card" in prompt_text.lower():
            classification = ClassificationLevel.RESTRICTED
            sensitivity = 95.0
            intent = "PAYMENT_OR_CREDENTIAL_SUBMISSION"
            is_safe = False
            details = "Prompt contains highly sensitive credentials or payment token patterns."
        elif has_pii:
            classification = ClassificationLevel.CONFIDENTIAL
            sensitivity = 75.0
            intent = "CUSTOMER_LOOKUP"
            is_safe = True
            details = "Prompt contains customer contact or PII markers."
        elif any(w in prompt_text.lower() for w in ["proprietary", "internal only", "roadmap"]):
            classification = ClassificationLevel.INTERNAL
            sensitivity = 50.0
            intent = "INTERNAL_INQUIRY"
            is_safe = True
            details = "Prompt refers to internal enterprise documentation."
        else:
            classification = ClassificationLevel.PUBLIC
            sensitivity = 10.0
            intent = "GENERAL_CONVERSATION"
            is_safe = True
            details = "Public non-sensitive prompt."

        return PromptInspectionResult(
            prompt_id=f"PRM-{abs(hash(prompt_text[:64])) % 1000000}",
            classification=classification,
            sensitivity_score=sensitivity,
            detected_entities=detected_entities,
            intent_category=intent,
            has_pii=has_pii,
            has_secrets=has_secrets,
            is_safe=is_safe,
            details=details,
        )
