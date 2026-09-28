"""AI Security Posture Evaluator.
Components 30.35 & 30.47: Evaluates enterprise AI assets against AI-SPM standard posture rules.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from ai_security.inventory.assets import AIAsset
from ai_security.posture.rules import AISPMRule, AISPMSeverity


@dataclass
class AISPMFinding:
    finding_id: str
    rule_id: str
    asset_id: str
    severity: AISPMSeverity
    title: str
    description: str
    remediation: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "asset_id": self.asset_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


class AISPMEvaluator:
    """Evaluates fleet-wide AI models, agents, and pipelines against compliance benchmarks."""

    def __init__(self, rules: Optional[List[AISPMRule]] = None):
        self.rules = rules or self._get_default_rules()

    def _get_default_rules(self) -> List[AISPMRule]:
        return [
            AISPMRule("AI-SPM-001", "Unapproved Model", "All deployed models must hold APPROVED status.", AISPMSeverity.HIGH, "Submit model for security governance review."),
            AISPMRule("AI-SPM-002", "Unknown Artifact Integrity", "Models must have verified cryptographic artifact hashes.", AISPMSeverity.CRITICAL, "Register baseline SHA-256 digest in registry."),
            AISPMRule("AI-SPM-003", "Excessive Agent Capabilities", "Agents should not hold more than 3 privileged tools.", AISPMSeverity.HIGH, "Refactor agent into modular single-purpose workers."),
            AISPMRule("AI-SPM-005", "External Model Restricted Data Leak", "Restricted data must never be routed to commercial external models.", AISPMSeverity.CRITICAL, "Enforce model routing to local sovereign infrastructure."),
            AISPMRule("AI-SPM-006", "Vector Store Tenant Isolation", "Vector collections must enforce multi-tenant isolation.", AISPMSeverity.HIGH, "Enable metadata filtering or separate collections per tenant."),
            AISPMRule("AI-SPM-007", "Unauthenticated Inference Endpoint", "Model endpoints must enforce authentication.", AISPMSeverity.CRITICAL, "Attach API gateway or mTLS sidecar."),
        ]

    def evaluate_asset(self, asset: AIAsset) -> List[AISPMFinding]:
        findings: List[AISPMFinding] = []
        asset_dict = asset.to_dict()

        for rule in self.rules:
            passed = rule.evaluate(asset_dict)
            if not passed:
                findings.append(
                    AISPMFinding(
                        finding_id=f"FIND-{rule.rule_id}-{asset.ai_asset_id}",
                        rule_id=rule.rule_id,
                        asset_id=asset.ai_asset_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        remediation=rule.remediation,
                    )
                )

        return findings
