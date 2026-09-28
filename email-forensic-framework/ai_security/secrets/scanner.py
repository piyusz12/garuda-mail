"""Garuda Enterprise AI Security - Secrets Security Scanner.
Phase 30 Section 30.44 (30.33): Scans prompts, tool inputs, agent memory,
and model configs for secrets, credentials, and tokens.
"""
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import re
import time
import uuid


class SecretType(str, Enum):
    API_KEY = "API_KEY"
    OPENAI_API_KEY = "OPENAI_API_KEY"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    DATABASE_PASSWORD = "DATABASE_PASSWORD"
    PRIVATE_KEY = "PRIVATE_KEY"
    JWT_BEARER_TOKEN = "JWT_BEARER_TOKEN"
    GITHUB_PAT = "GITHUB_PAT"


class SecretAction(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    ALERT = "ALERT"


@dataclass
class DetectedSecret:
    secret_id: str
    secret_type: SecretType
    matched_pattern: str
    start_pos: int
    end_pos: int
    confidence: float
    masked_value: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "secret_type": self.secret_type.value,
            "matched_pattern": self.matched_pattern,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "confidence": self.confidence,
            "masked_value": self.masked_value,
        }


@dataclass
class SecretScanResult:
    has_secret: bool
    action: SecretAction
    secrets_found: List[DetectedSecret] = field(default_factory=list)
    sanitized_text: str = ""
    scan_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_secret": self.has_secret,
            "action": self.action.value,
            "secrets_count": len(self.secrets_found),
            "secrets_found": [s.to_dict() for s in self.secrets_found],
            "sanitized_text": self.sanitized_text,
            "scan_time_ms": self.scan_time_ms,
        }


class AISecretsScanner:
    """Detects and redacts credentials, keys, and tokens across AI payloads."""

    PATTERNS = [
        (SecretType.OPENAI_API_KEY, r"sk-[a-zA-Z0-9]{32,64}", 0.95),
        (SecretType.AWS_ACCESS_KEY, r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", 0.98),
        (SecretType.GITHUB_PAT, r"ghp_[a-zA-Z0-9]{36,40}", 0.98),
        (SecretType.JWT_BEARER_TOKEN, r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", 0.92),
        (SecretType.PRIVATE_KEY, r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", 0.99),
        (SecretType.DATABASE_PASSWORD, r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,32})['\"]", 0.85),
        (SecretType.API_KEY, r"(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,64})['\"]", 0.88),
    ]

    def __init__(self, default_action: SecretAction = SecretAction.BLOCK):
        self.default_action = default_action

    def scan(self, text: str) -> SecretScanResult:
        start_t = time.time()
        detected: List[DetectedSecret] = []
        sanitized = text

        for sec_type, regex, conf in self.PATTERNS:
            for match in re.finditer(regex, text, re.IGNORECASE):
                val = match.group(0)
                masked = val[:4] + "*" * (len(val) - 6) + val[-2:] if len(val) > 8 else "***REDACTED***"
                detected.append(
                    DetectedSecret(
                        secret_id=f"SEC-{uuid.uuid4().hex[:6].upper()}",
                        secret_type=sec_type,
                        matched_pattern=regex,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        confidence=conf,
                        masked_value=masked,
                    )
                )
                sanitized = sanitized.replace(val, masked)

        elapsed = (time.time() - start_t) * 1000.0
        has_sec = len(detected) > 0
        action = self.default_action if has_sec else SecretAction.ALLOW

        return SecretScanResult(
            has_secret=has_sec,
            action=action,
            secrets_found=detected,
            sanitized_text=sanitized,
            scan_time_ms=elapsed,
        )
