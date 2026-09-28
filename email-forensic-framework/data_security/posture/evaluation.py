"""
Data Security Posture Management (DSPM) Evaluation Engine.
Component 29.13: Evaluates data assets against enterprise security posture baselines.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from data_security.inventory.normalization import DataAsset, ClassificationLevel
from data_security.posture.rules import DSPMRule, DSPMSeverity


@dataclass
class DSPMFinding:
    finding_id: str
    rule_id: str
    asset_id: str
    severity: DSPMSeverity
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


class DSPMEvaluator:
    """Evaluates data assets against DSPM compliance checks and posture policies."""

    def __init__(self, rules: Optional[List[DSPMRule]] = None):
        self.rules = rules or self._get_default_rules()

    def _get_default_rules(self) -> List[DSPMRule]:
        return [
            DSPMRule("DSPM-001", "Sensitive Data Ownership", "Sensitive datasets must have an assigned business owner.", DSPMSeverity.HIGH, "Assign a verified business and technical owner."),
            DSPMRule("DSPM-002", "Excessive Access Breadth", "Sensitive datasets must not be accessible to over 10 distinct entities.", DSPMSeverity.HIGH, "Revoke unnecessary IAM role bindings."),
            DSPMRule("DSPM-003", "Public Storage Exposure", "Sensitive and restricted data stores must never be publicly exposed.", DSPMSeverity.CRITICAL, "Enable S3 Block Public Access and attach private VPC endpoint."),
            DSPMRule("DSPM-004", "Encryption at Rest Enforcement", "Restricted data must be encrypted with enterprise KMS keys.", DSPMSeverity.CRITICAL, "Enable KMS encryption with approved key."),
            DSPMRule("DSPM-006", "Stale Dataset Retention", "Datasets exceeding their approved retention period must be archived or deleted.", DSPMSeverity.MEDIUM, "Trigger compliant deletion lifecycle."),
        ]

    def evaluate_asset(self, asset: DataAsset, context: Optional[Dict[str, Any]] = None) -> List[DSPMFinding]:
        findings: List[DSPMFinding] = []
        asset_dict = asset.to_dict()
        if context:
            asset_dict.update(context)

        for rule in self.rules:
            passed = rule.evaluate_asset(asset_dict)
            if not passed:
                findings.append(
                    DSPMFinding(
                        finding_id=f"FIND-{rule.rule_id}-{asset.data_asset_id}",
                        rule_id=rule.rule_id,
                        asset_id=asset.data_asset_id,
                        severity=rule.severity,
                        title=f"{rule.name} Violation on {asset.name}",
                        description=f"Asset {asset.data_asset_id} failed check: {rule.description}",
                        remediation=rule.remediation,
                    )
                )
        return findings

    def evaluate_fleet(self, assets: List[DataAsset]) -> Dict[str, Any]:
        all_findings = []
        for a in assets:
            all_findings.extend(self.evaluate_asset(a))

        compliance_pct = round(((len(assets) * len(self.rules) - len(all_findings)) / max(1, len(assets) * len(self.rules))) * 100, 1)

        return {
            "total_assets_evaluated": len(assets),
            "total_checks": len(assets) * len(self.rules),
            "violations_count": len(all_findings),
            "compliance_score_pct": compliance_pct,
            "violations": [f.to_dict() for f in all_findings],
        }
