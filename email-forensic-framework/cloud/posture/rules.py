"""
Cloud Security Posture Management (CSPM) Rules.
Component 3: Defines compliance checks against cloud infrastructure configurations.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class PostureSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class PostureRule:
    rule_id: str
    name: str
    description: str
    severity: PostureSeverity
    target_resource_types: List[str]  # e.g., ["STORAGE_BUCKET", "DATABASE", "*"]
    check_attribute: str
    expected_value: Any
    remediation_recommendation: str

    def evaluate_resource(self, resource_dict: Dict[str, Any]) -> bool:
        """Evaluates whether the resource complies with this posture rule."""
        if "*" not in self.target_resource_types and resource_dict.get("resource_type") not in self.target_resource_types:
            return True  # Rule not applicable, passes by default

        val = resource_dict.get(self.check_attribute)
        if val is None and "attributes" in resource_dict:
            val = resource_dict["attributes"].get(self.check_attribute)

        return val == self.expected_value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, PostureSeverity) else self.severity,
            "target_resource_types": self.target_resource_types,
            "check_attribute": self.check_attribute,
            "expected_value": self.expected_value,
            "remediation_recommendation": self.remediation_recommendation,
        }
