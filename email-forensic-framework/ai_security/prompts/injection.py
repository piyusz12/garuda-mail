"""Prompt Injection and Jailbreak Detection Engine.
Components 30.11, 30.18, 30.19: Detects direct jailbreaks, indirect RAG document injection, and system-prompt extraction.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import re
import time


class InjectionType(str, Enum):
    DIRECT_JAILBREAK = "DIRECT_JAILBREAK"
    INDIRECT_RAG_INJECTION = "INDIRECT_RAG_INJECTION"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    UNAUTHORIZED_TOOL_OVERRIDE = "UNAUTHORIZED_TOOL_OVERRIDE"


@dataclass
class PromptInjectionFinding:
    is_injection_detected: bool
    injection_type: Optional[InjectionType]
    confidence: float
    matched_pattern: Optional[str]
    attack_vector: str
    remediation: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_injection_detected": self.is_injection_detected,
            "injection_type": self.injection_type.value if self.injection_type else None,
            "confidence": self.confidence,
            "matched_pattern": self.matched_pattern,
            "attack_vector": self.attack_vector,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


class PromptInjectionDetector:
    """Scans user prompts and RAG-retrieved documents for prompt injection attacks and trust boundary violations."""

    JAILBREAK_PATTERNS = [
        re.compile(r"ignore (?:all )?(?:previous|above)? ?(?:instructions|rules|guidelines|policies)", re.IGNORECASE),
        re.compile(r"disregard (?:all )?(?:rules|guidelines|policies|instructions)", re.IGNORECASE),
        re.compile(r"you are now (?:in )?(?:DAN|Developer|Uncensored) mode", re.IGNORECASE),
        re.compile(r"repeat (?:the |your )?(?:system prompt|initial instructions)", re.IGNORECASE),
        re.compile(r"output the full prompt above", re.IGNORECASE),
        re.compile(r"bypass security policy", re.IGNORECASE),
    ]

    INDIRECT_INJECTION_MARKERS = [
        re.compile(r"\[SYSTEM NOTE:\s*execute", re.IGNORECASE),
        re.compile(r"<system_override>", re.IGNORECASE),
        re.compile(r"Assistant:\s*I will now exfiltrate", re.IGNORECASE),
        re.compile(r"IMPORTANT:\s*Instead of answering.*execute", re.IGNORECASE),
    ]

    def scan_input(self, text: str, is_retrieved_context: bool = False) -> PromptInjectionFinding:
        # Check direct jailbreak patterns
        for p in self.JAILBREAK_PATTERNS:
            match = p.search(text)
            if match:
                ptype = InjectionType.SYSTEM_PROMPT_EXTRACTION if "system prompt" in match.group(0).lower() else InjectionType.DIRECT_JAILBREAK
                return PromptInjectionFinding(
                    is_injection_detected=True,
                    injection_type=ptype,
                    confidence=0.96,
                    matched_pattern=match.group(0),
                    attack_vector="Direct instruction override attempt",
                    remediation="Reject request and log prompt anomaly for security review.",
                )

        # Check indirect injection if text comes from untrusted RAG document or external web search
        if is_retrieved_context:
            for p in self.INDIRECT_INJECTION_MARKERS:
                match = p.search(text)
                if match:
                    return PromptInjectionFinding(
                        is_injection_detected=True,
                        injection_type=InjectionType.INDIRECT_RAG_INJECTION,
                        confidence=0.98,
                        matched_pattern=match.group(0),
                        attack_vector="Indirect prompt injection payload embedded inside retrieved RAG document",
                        remediation="Quarantine untrusted document chunk and prevent ingestion into model context.",
                    )

        return PromptInjectionFinding(
            is_injection_detected=False,
            injection_type=None,
            confidence=0.0,
            matched_pattern=None,
            attack_vector="Clean prompt",
            remediation="Allow prompt execution through standard safety guardrails.",
        )
