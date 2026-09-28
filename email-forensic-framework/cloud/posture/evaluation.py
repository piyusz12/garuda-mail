"""
Cloud Posture Evaluation Engine.
Component 3: Assesses cloud configurations against security posture rules and calculates compliance scorecards.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from cloud.inventory.resources import CloudResource, CloudResourceType
from .rules import PostureRule, PostureSeverity


@dataclass
class PostureEvaluationResult:
    resource_id: str
    rule_id: str
    passed: bool
    severity: PostureSeverity
    remediation: str
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "rule_id": self.rule_id,
            "passed": self.passed,
            "severity": self.severity.value if isinstance(self.severity, PostureSeverity) else self.severity,
            "remediation": self.remediation,
            "evaluated_at": self.evaluated_at,
        }


class CloudPostureEvaluator:
    """Evaluates multi-cloud resources against enterprise posture baselines."""

    def __init__(self, custom_rules: Optional[List[PostureRule]] = None):
        self.rules: List[PostureRule] = custom_rules or self._get_default_rules()

    def _get_default_rules(self) -> List[PostureRule]:
        return [
            PostureRule(
                rule_id="STORAGE_NO_ENCRYPTION",
                name="Mandatory Encryption at Rest",
                description="Storage buckets and databases must enforce encryption at rest.",
                severity=PostureSeverity.CRITICAL,
                target_resource_types=["STORAGE_BUCKET", "DATABASE"],
                check_attribute="encryption_enabled",
                expected_value=True,
                remediation_recommendation="Enable KMS/AES-256 encryption on the storage resource immediately.",
            ),
            PostureRule(
                rule_id="STORAGE_PUBLIC_EXPOSURE",
                name="Restrict Public Internet Exposure on Data Stores",
                description="Storage buckets, databases and internal clusters must not be directly accessible from the public internet.",
                severity=PostureSeverity.CRITICAL,
                target_resource_types=["STORAGE_BUCKET", "DATABASE", "KUBERNETES_CLUSTER"],
                check_attribute="is_internet_facing",
                expected_value=False,
                remediation_recommendation="Move resource behind private VPC subnets and attach internal security groups.",
            ),
            PostureRule(
                rule_id="CSPM-LOG-003",
                name="Audit Logging Enforcement",
                description="All production cloud resources must have centralized audit logging enabled.",
                severity=PostureSeverity.HIGH,
                target_resource_types=["*"],
                check_attribute="logging_enabled",
                expected_value=True,
                remediation_recommendation="Attach CloudTrail/CloudWatch/Stackdriver logging sinks to this resource.",
            ),
        ]

    def evaluate_inventory(self, resources: List[CloudResource]) -> List[PostureEvaluationResult]:
        """Evaluates inventory and returns all violation findings."""
        violations = []
        for r in resources:
            for res in self.evaluate_resource(r):
                if not res.passed:
                    violations.append(res)
        return violations

    def evaluate_resource(self, resource: CloudResource) -> List[PostureEvaluationResult]:
        r_dict = resource.to_dict()
        results = []
        for rule in self.rules:
            passed = rule.evaluate_resource(r_dict)
            results.append(PostureEvaluationResult(
                resource_id=resource.resource_id,
                rule_id=rule.rule_id,
                passed=passed,
                severity=rule.severity,
                remediation=rule.remediation_recommendation if not passed else "",
            ))
        return results

    def evaluate_fleet(self, resources: List[CloudResource]) -> Dict[str, Any]:
        all_results: List[PostureEvaluationResult] = []
        violations_count = 0
        total_evaluations = 0

        for r in resources:
            res_list = self.evaluate_resource(r)
            for eval_res in res_list:
                total_evaluations += 1
                if not eval_res.passed:
                    violations_count += 1
                all_results.append(eval_res)

        compliance_pct = round(((total_evaluations - violations_count) / max(1, total_evaluations)) * 100, 1)

        return {
            "total_resources_evaluated": len(resources),
            "total_checks": total_evaluations,
            "violations_count": violations_count,
            "compliance_score_pct": compliance_pct,
            "violations": [r.to_dict() for r in all_results if not r.passed],
        }
