"""AI Security Posture Management (AI-SPM) Rules.
Components 30.35 & 30.46: Standard posture rules for models, agents, vector stores, and AI endpoints.
"""
from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum


class AISPMSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AISPMRule:
    rule_id: str
    title: str
    description: str
    severity: AISPMSeverity
    remediation: str

    def evaluate(self, asset_dict: Dict[str, Any]) -> bool:
        """Returns True if compliant, False if violation."""
        asset_type = asset_dict.get("asset_type")

        if self.rule_id == "AI-SPM-001":  # Unapproved model
            if asset_type == "LLM":
                return asset_dict.get("status") in ("APPROVED", "ACTIVE")
            return True

        elif self.rule_id == "AI-SPM-002":  # Model artifact integrity unknown
            if asset_type == "LLM":
                meta = asset_dict.get("metadata", {})
                return bool(meta.get("artifact_hash"))
            return True

        elif self.rule_id == "AI-SPM-003":  # Agent has excessive tools
            if asset_type == "AGENT":
                meta = asset_dict.get("metadata", {})
                tools = meta.get("tools", [])
                return len(tools) <= 3
            return True

        elif self.rule_id == "AI-SPM-005":  # Restricted data sent to external model
            is_external = asset_dict.get("is_external", False)
            if is_external and asset_dict.get("classification") == "RESTRICTED":
                return False
            return True

        elif self.rule_id == "AI-SPM-006":  # Vector store lacks tenant isolation
            if asset_type == "VECTOR_STORE":
                meta = asset_dict.get("metadata", {})
                return meta.get("tenant_isolation", False)
            return True

        elif self.rule_id == "AI-SPM-007":  # AI endpoint lacks authentication
            if asset_type == "MODEL_SERVER":
                return asset_dict.get("requires_authentication", True)
            return True

        return True
