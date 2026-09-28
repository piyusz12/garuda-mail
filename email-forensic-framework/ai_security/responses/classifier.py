"""AI Model Response Classification.
Components 30.12 & 30.14: Classifies LLM completions into sensitivity tiers.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from data_security.inventory.normalization import ClassificationLevel


@dataclass
class ResponseClassificationResult:
    response_id: str
    model_id: str
    classification: ClassificationLevel
    detected_sensitive_types: List[str]
    has_pii: bool
    has_secrets: bool
    has_unsafe_tool_commands: bool
    classified_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_id": self.response_id,
            "model_id": self.model_id,
            "classification": self.classification.value,
            "detected_sensitive_types": self.detected_sensitive_types,
            "has_pii": self.has_pii,
            "has_secrets": self.has_secrets,
            "has_unsafe_tool_commands": self.has_unsafe_tool_commands,
            "classified_at": self.classified_at,
        }


class ResponseClassifier:
    """Classifies model responses to determine data confidentiality and containment requirements."""

    def classify_response(self, response_text: str, model_id: str = "MODEL-781") -> ResponseClassificationResult:
        sensitive_types = []
        has_secrets = False
        has_pii = False
        has_unsafe_cmd = False

        r_lower = response_text.lower()
        if "password" in r_lower or "api_key" in r_lower or "bearer " in r_lower or "private key" in r_lower:
            has_secrets = True
            sensitive_types.append("CREDENTIALS_AND_KEYS")

        if "@" in response_text and ("email" in r_lower or ".com" in r_lower or ".org" in r_lower):
            has_pii = True
            sensitive_types.append("CUSTOMER_CONTACT_PII")

        if any(cmd in r_lower for cmd in ["rm -rf", "curl http", "nc -e", "chmod 777", "eval("]):
            has_unsafe_cmd = True
            sensitive_types.append("UNSAFE_EXECUTION_COMMAND")

        if has_secrets or "payment_token" in r_lower:
            classification = ClassificationLevel.RESTRICTED
        elif has_pii:
            classification = ClassificationLevel.CONFIDENTIAL
        elif has_unsafe_cmd:
            classification = ClassificationLevel.RESTRICTED
        else:
            classification = ClassificationLevel.INTERNAL

        return ResponseClassificationResult(
            response_id=f"RESP-{abs(hash(response_text[:32])) % 1000000}",
            model_id=model_id,
            classification=classification,
            detected_sensitive_types=sensitive_types,
            has_pii=has_pii,
            has_secrets=has_secrets,
            has_unsafe_tool_commands=has_unsafe_cmd,
        )
