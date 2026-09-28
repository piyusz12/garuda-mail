"""AI Model Supply Chain Scanner.
Components 30.5 & 30.12: Validates model download sources, registry signatures, and detects unapproved models.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AISupplyChainFindingType(str, Enum):
    UNKNOWN_SOURCE = "AI-SC-001"
    HASH_TAMPERED = "AI-SC-002"
    UNAPPROVED_MODEL = "AI-SC-003"
    UNREGISTERED_DEPLOYMENT = "AI-SC-004"
    VERSION_MISMATCH = "AI-SC-005"


@dataclass
class AISupplyChainFinding:
    finding_id: str
    finding_type: AISupplyChainFindingType
    model_id: str
    severity: str  # "HIGH", "CRITICAL", "MEDIUM"
    title: str
    description: str
    remediation: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "model_id": self.model_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


class ModelSupplyChainScanner:
    """Scans the AI artifact lifecycle: Source -> Download -> Validation -> Registry -> Deploy."""

    def __init__(self, approved_registries: Optional[List[str]] = None):
        self.approved_registries = approved_registries or [
            "internal-artifactory/models",
            "garuda-ecr.prod/models",
        ]

    def audit_model_deployment(
        self,
        model_id: str,
        source_url: str,
        is_in_registry: bool,
        is_integrity_valid: bool,
    ) -> List[AISupplyChainFinding]:
        findings: List[AISupplyChainFinding] = []

        # Check approval in registry
        if not is_in_registry:
            findings.append(
                AISupplyChainFinding(
                    finding_id=f"FIND-SC-UNAPP-{model_id}",
                    finding_type=AISupplyChainFindingType.UNAPPROVED_MODEL,
                    model_id=model_id,
                    severity="HIGH",
                    title="Unapproved Model Introduced",
                    description=f"Model {model_id} was deployed without passing through enterprise AI governance approval.",
                    remediation="Submit model to SecOps for architectural review and provenance sign-off.",
                )
            )

        # Check source repository
        is_approved_source = any(reg in source_url for reg in self.approved_registries)
        if not is_approved_source:
            findings.append(
                AISupplyChainFinding(
                    finding_id=f"FIND-SC-SRC-{model_id}",
                    finding_type=AISupplyChainFindingType.UNKNOWN_SOURCE,
                    model_id=model_id,
                    severity="HIGH",
                    title="Model Source Untrusted",
                    description=f"Model {model_id} was downloaded from unapproved endpoint {source_url}.",
                    remediation="Relocate model weights into the internal verified Artifactory mirror.",
                )
            )

        # Check integrity
        if not is_integrity_valid:
            findings.append(
                AISupplyChainFinding(
                    finding_id=f"FIND-SC-TAMPER-{model_id}",
                    finding_type=AISupplyChainFindingType.HASH_TAMPERED,
                    model_id=model_id,
                    severity="CRITICAL",
                    title="Artifact Hash Mismatch Detected",
                    description=f"Model {model_id} runtime weights have drifted or been modified post-approval.",
                    remediation="Immediately quarantine container and rebuild pod from golden signed image.",
                )
            )

        return findings
