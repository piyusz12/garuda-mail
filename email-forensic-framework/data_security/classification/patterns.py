"""
Sensitive Data Detection Patterns and Heuristics.
Component 29.4 & 29.10: Recognizes identity, financial, auth, crypto, and health data patterns.
"""
import re
from typing import Dict, List, Pattern, Any
from dataclasses import dataclass


@dataclass
class PatternDefinition:
    category: str
    pattern_name: str
    regex: Pattern
    confidence_weight: float
    description: str


class SensitiveDataPatterns:
    """Library of compiled regular expressions for PII, credentials, financial, and secrets."""

    PATTERNS = [
        PatternDefinition(
            category="IDENTITY_CONTACT",
            pattern_name="EMAIL_ADDRESS",
            regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,15}\b"),
            confidence_weight=0.95,
            description="Standard email address format",
        ),
        PatternDefinition(
            category="IDENTITY_CONTACT",
            pattern_name="PHONE_NUMBER",
            regex=re.compile(r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b"),
            confidence_weight=0.85,
            description="E.164 and standard telephone formats",
        ),
        PatternDefinition(
            category="FINANCIAL_PAYMENT",
            pattern_name="CREDIT_CARD_NUMBER",
            regex=re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
            confidence_weight=0.98,
            description="Visa, Mastercard, AMEX payment card numbers",
        ),
        PatternDefinition(
            category="FINANCIAL_PAYMENT",
            pattern_name="IBAN_CODE",
            regex=re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"),
            confidence_weight=0.92,
            description="International Bank Account Number",
        ),
        PatternDefinition(
            category="CREDENTIALS_AUTH",
            pattern_name="API_BEARER_TOKEN",
            regex=re.compile(r"\b(?:bearer\s+)?[a-zA-Z0-9_\-\.]{32,128}\b", re.IGNORECASE),
            confidence_weight=0.80,
            description="High-entropy API token or secret string",
        ),
        PatternDefinition(
            category="CREDENTIALS_AUTH",
            pattern_name="PRIVATE_KEY_HEADER",
            regex=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            confidence_weight=1.0,
            description="Asymmetric private key certificate block",
        ),
    ]

    # Keyword mappings for column/field schemas
    COLUMN_NAME_SIGNALS = {
        "email": ("IDENTITY_CONTACT", 0.95),
        "mail": ("IDENTITY_CONTACT", 0.90),
        "phone": ("IDENTITY_CONTACT", 0.90),
        "mobile": ("IDENTITY_CONTACT", 0.90),
        "ssn": ("IDENTITY_GOVERNMENT", 0.99),
        "national_id": ("IDENTITY_GOVERNMENT", 0.95),
        "passport": ("IDENTITY_GOVERNMENT", 0.95),
        "credit_card": ("FINANCIAL_PAYMENT", 0.99),
        "card_num": ("FINANCIAL_PAYMENT", 0.98),
        "payment_token": ("FINANCIAL_PAYMENT", 0.95),
        "password": ("CREDENTIALS_AUTH", 1.0),
        "secret": ("CREDENTIALS_AUTH", 0.95),
        "token": ("CREDENTIALS_AUTH", 0.85),
        "api_key": ("CREDENTIALS_AUTH", 0.98),
        "private_key": ("CREDENTIALS_AUTH", 1.0),
        "diagnosis": ("HEALTH_MEDICAL", 0.95),
        "patient": ("HEALTH_MEDICAL", 0.90),
    }
