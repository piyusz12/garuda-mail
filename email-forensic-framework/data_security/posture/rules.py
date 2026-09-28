"""
Data Security Posture Management (DSPM) Rules.
Component 29.13 & 29.28: Evaluates data assets for encryption, public exposure, ownership, and retention.
"""
from dataclasses import dataclass
from typing import Dict, List, Any
from enum import Enum


class DSPMSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DSPMRule:
    rule_id: str
    name: str
    description: str
    severity: DSPMSeverity
    remediation: str

    def evaluate_asset(self, asset_dict: Dict[str, Any]) -> bool:
        """Returns True if COMPLIANT, False if VIOLATION."""
        classification = asset_dict.get("classification", "INTERNAL")
        is_sensitive = classification in ("RESTRICTED", "SENSITIVE", "CONFIDENTIAL")

        if self.rule_id == "DSPM-001":  # Sensitive data without owner
            if is_sensitive:
                owner = asset_dict.get("business_owner", "")
                return bool(owner and owner != "unknown" and "@" in owner or "-" in owner)
            return True

        elif self.rule_id == "DSPM-002":  # Sensitive data with excessive access
            if is_sensitive:
                effective_count = asset_dict.get("effective_identities_count", 1)
                return effective_count <= 10
            return True

        elif self.rule_id == "DSPM-003":  # Sensitive data in public storage
            if is_sensitive:
                return not asset_dict.get("is_publicly_exposed", False)
            return True

        elif self.rule_id == "DSPM-004":  # Sensitive data without encryption at rest
            if is_sensitive:
                return bool(asset_dict.get("encryption_at_rest", True))
            return True

        elif self.rule_id == "DSPM-006":  # Stale sensitive dataset
            if is_sensitive:
                retention_days = asset_dict.get("retention_days", 365)
                age_days = (asset_dict.get("age_seconds", 0)) / 86400
                return age_days <= retention_days
            return True

        return True
