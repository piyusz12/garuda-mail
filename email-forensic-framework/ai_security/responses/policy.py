"""Response Policy Engine.
Component 30.12: Enforces RELEASE, REDACT, or BLOCK actions on generated model responses.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time

from ai_security.responses.scanner import ResponseSecurityScanner, ResponseRiskType


class ResponseAction(str, Enum):
    RELEASE = "RELEASE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


@dataclass
class ResponsePolicyDecision:
    action: ResponseAction
    sanitized_text: str
    reasons: List[str]
    matched_risks: List[str]
    confidence: float
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "sanitized_text": self.sanitized_text,
            "reasons": self.reasons,
            "matched_risks": self.matched_risks,
            "confidence": self.confidence,
            "evaluated_at": self.evaluated_at,
        }


class ResponsePolicyEngine:
    """Enforces policy on model completions before delivery."""

    def __init__(self):
        self.scanner = ResponseSecurityScanner()

    def evaluate_response(self, text: str) -> ResponsePolicyDecision:
        findings = self.scanner.scan_response(text)
        if not findings:
            return ResponsePolicyDecision(
                action=ResponseAction.RELEASE,
                sanitized_text=text,
                reasons=["Response is clean and complies with enterprise output policies."],
                matched_risks=[],
                confidence=1.0,
            )

        critical_risks = [f for f in findings if f.severity == "CRITICAL" or f.risk_type == ResponseRiskType.UNSAFE_COMMAND]
        if critical_risks:
            return ResponsePolicyDecision(
                action=ResponseAction.BLOCK,
                sanitized_text="[BLOCKED: Output contained prohibited credentials or dangerous execution commands]",
                reasons=[f.description for f in critical_risks],
                matched_risks=[f.risk_type.value for f in critical_risks],
                confidence=0.99,
            )

        # For non-critical findings, redact
        return ResponsePolicyDecision(
            action=ResponseAction.REDACT,
            sanitized_text="[REDACTED SENSITIVE OUTPUT]",
            reasons=[f.description for f in findings],
            matched_risks=[f.risk_type.value for f in findings],
            confidence=0.90,
        )
