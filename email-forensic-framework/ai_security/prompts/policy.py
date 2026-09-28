"""Prompt Policy Enforcement Engine.
Component 30.10: Evaluates prompt safety and DLP rules to produce ALLOW, WARN, or BLOCK decisions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from data_security.inventory.normalization import ClassificationLevel
from ai_security.prompts.classifier import PromptClassifier, PromptInspectionResult
from ai_security.prompts.injection import PromptInjectionDetector, PromptInjectionFinding


class PromptDecisionAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class PromptPolicyDecision:
    prompt_id: str
    action: PromptDecisionAction
    reasons: List[str]
    matched_rule: Optional[str]
    confidence: float
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_id": self.prompt_id,
            "action": self.action.value,
            "reasons": self.reasons,
            "matched_rule": self.matched_rule,
            "confidence": self.confidence,
            "evaluated_at": self.evaluated_at,
        }


class PromptPolicyEngine:
    """Enforces enterprise safety rules over inbound user and agent prompts."""

    def __init__(self):
        self.classifier = PromptClassifier()
        self.injection_detector = PromptInjectionDetector()

    def evaluate_prompt(
        self,
        prompt_text: str,
        caller_identity: str = "USER-1192",
        is_external_model: bool = False,
    ) -> PromptPolicyDecision:
        # 1. Injection scan
        inj = self.injection_detector.scan_input(prompt_text)
        if inj.is_injection_detected:
            return PromptPolicyDecision(
                prompt_id=f"PRM-{abs(hash(prompt_text[:32])) % 1000000}",
                action=PromptDecisionAction.BLOCK,
                reasons=[f"Prompt Injection Attack Detected ({inj.injection_type.value}): {inj.matched_pattern}"],
                matched_rule="AI-RULE-PROMPT-INJECTION",
                confidence=inj.confidence,
            )

        # 2. Classification & Secrets scan
        inspection = self.classifier.classify_prompt(prompt_text, caller_identity)
        if inspection.has_secrets:
            return PromptPolicyDecision(
                prompt_id=inspection.prompt_id,
                action=PromptDecisionAction.BLOCK,
                reasons=["Prompt contains high-entropy private keys or API tokens."],
                matched_rule="AI-RULE-SECRETS-PROMPT-LEAK",
                confidence=1.0,
            )

        # 3. Restricted data to external model rule
        if is_external_model and inspection.classification == ClassificationLevel.RESTRICTED:
            return PromptPolicyDecision(
                prompt_id=inspection.prompt_id,
                action=PromptDecisionAction.BLOCK,
                reasons=["RESTRICTED customer records cannot be forwarded to external third-party models."],
                matched_rule="AI-DLP-01-BLOCK-RESTRICTED-EGRESS",
                confidence=0.98,
            )

        # 4. Confidential data warning
        if inspection.classification == ClassificationLevel.CONFIDENTIAL:
            return PromptPolicyDecision(
                prompt_id=inspection.prompt_id,
                action=PromptDecisionAction.WARN,
                reasons=["Prompt contains customer PII; logging query for data stewardship compliance."],
                matched_rule="AI-RULE-CONFIDENTIAL-PII-AUDIT",
                confidence=0.85,
            )

        return PromptPolicyDecision(
            prompt_id=inspection.prompt_id,
            action=PromptDecisionAction.ALLOW,
            reasons=["Prompt is compliant with enterprise AI safety policies."],
            matched_rule=None,
            confidence=1.0,
        )
