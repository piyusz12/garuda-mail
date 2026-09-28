"""
Serverless Least-Privilege and Configuration Auditor.
Component 33: Audits execution roles, VPC isolation, and public trigger exposure.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid

from serverless.functions import ServerlessFunction, FunctionRepository
from serverless.triggers import FunctionTrigger, TriggerType


class ServerlessFindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ServerlessFinding:
    finding_id: str
    function_id: str
    severity: ServerlessFindingSeverity
    rule_id: str
    title: str
    description: str
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "function_id": self.function_id,
            "severity": self.severity.value if isinstance(self.severity, ServerlessFindingSeverity) else self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
        }


class ServerlessPermissionAuditor:
    """Audits serverless functions for IAM privilege excess, VPC isolation, and insecure environment secrets."""

    def audit_function(
        self,
        function: ServerlessFunction,
        triggers: Optional[List[FunctionTrigger]] = None,
    ) -> List[ServerlessFinding]:
        findings: List[ServerlessFinding] = []

        # 1. Broad IAM execution role
        if "admin" in function.execution_role_arn.lower() or "broad" in function.execution_role_arn.lower():
            findings.append(
                ServerlessFinding(
                    finding_id=f"SLSFIND-{uuid.uuid4().hex[:8].upper()}",
                    function_id=function.function_id,
                    severity=ServerlessFindingSeverity.HIGH,
                    rule_id="SERVERLESS_OVERPRIVILEGED_ROLE",
                    title=f"Overprivileged Execution Role assigned to {function.name}",
                    description=f"Function assumes broad administrative role: {function.execution_role_arn}",
                    evidence={"execution_role_arn": function.execution_role_arn},
                )
            )

        # 2. Non-VPC connected function in enterprise production
        if not function.is_vpc_connected and function.tags.get("Environment") == "production":
            findings.append(
                ServerlessFinding(
                    finding_id=f"SLSFIND-{uuid.uuid4().hex[:8].upper()}",
                    function_id=function.function_id,
                    severity=ServerlessFindingSeverity.MEDIUM,
                    rule_id="SERVERLESS_OUTSIDE_VPC",
                    title=f"Production function {function.name} executes outside VPC",
                    description="Function has direct public internet routing instead of dedicated private VPC subnets.",
                    evidence={"is_vpc_connected": function.is_vpc_connected},
                )
            )

        # 3. Plaintext secrets in environment variables
        secret_keys = [k for k in function.environment_variables.keys() if any(s in k.upper() for s in ["PASSWORD", "TOKEN", "PRIVATE_KEY"])]
        if secret_keys:
            findings.append(
                ServerlessFinding(
                    finding_id=f"SLSFIND-{uuid.uuid4().hex[:8].upper()}",
                    function_id=function.function_id,
                    severity=ServerlessFindingSeverity.HIGH,
                    rule_id="SERVERLESS_PLAINTEXT_SECRET",
                    title=f"Plaintext secrets detected in environment variables of {function.name}",
                    description=f"Environment variables contain sensitive keys: {secret_keys}. Use Cloud KMS or Secrets Manager instead.",
                    evidence={"keys": secret_keys},
                )
            )

        # 4. Unauthenticated public triggers
        if triggers:
            for trig in triggers:
                if trig.is_public and not trig.auth_required:
                    findings.append(
                        ServerlessFinding(
                            finding_id=f"SLSFIND-{uuid.uuid4().hex[:8].upper()}",
                            function_id=function.function_id,
                            severity=ServerlessFindingSeverity.CRITICAL,
                            rule_id="SERVERLESS_PUBLIC_UNAUTH_TRIGGER",
                            title=f"Unauthenticated public invocation trigger on {function.name}",
                            description=f"Trigger {trig.trigger_id} allows unauthenticated public invocations from {trig.source_arn}.",
                            evidence=trig.to_dict(),
                        )
                    )

        return findings
