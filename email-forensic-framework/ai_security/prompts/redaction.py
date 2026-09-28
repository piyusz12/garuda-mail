"""Prompt Redaction and Sanitization Engine.
Component 30.10: Redacts secrets, credentials, and sensitive PII from prompts prior to inference.
"""
import re
from typing import Tuple, List


class PromptRedactionEngine:
    """Masks or redacts sensitive identifiers and credentials from prompts."""

    REPLACEMENT_PATTERNS = [
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,15}\b"), "[REDACTED_EMAIL]"),
        (re.compile(r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b"), "[REDACTED_PHONE]"),
        (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[REDACTED_CARD]"),
        (re.compile(r"(?:api_key|access_token|secret_key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{16,}['\"]?", re.IGNORECASE), "api_key=[REDACTED_SECRET]"),
        (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED_GITHUB_TOKEN]"),
    ]

    @classmethod
    def redact_prompt(cls, prompt_text: str) -> Tuple[str, int]:
        sanitized = prompt_text
        redactions_count = 0

        for pattern, replacement in cls.REPLACEMENT_PATTERNS:
            matches = len(pattern.findall(sanitized))
            if matches > 0:
                sanitized = pattern.sub(replacement, sanitized)
                redactions_count += matches

        return sanitized, redactions_count
