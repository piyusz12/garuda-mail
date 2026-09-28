"""
Cloud IAM Roles and Policy Modeling.
Component 5: Connects enterprise identities to cloud provider IAM roles and permissions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class CloudIAMRole:
    role_id: str
    role_name: str
    arn_or_uri: str
    account_id: str
    is_privileged: bool = False
    permissions: List[str] = field(default_factory=list)
    trust_policy: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_id": self.role_id,
            "role_name": self.role_name,
            "arn_or_uri": self.arn_or_uri,
            "account_id": self.account_id,
            "is_privileged": self.is_privileged,
            "permissions_count": len(self.permissions),
            "permissions": self.permissions,
        }


class CloudRoleRepository:
    """Registry for cloud IAM roles."""

    def __init__(self):
        self._roles: Dict[str, CloudIAMRole] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            CloudIAMRole(
                role_id="ROLE-K8S-ADMIN-01",
                role_name="GarudaK8sClusterAdminRole",
                arn_or_uri="arn:aws:iam::112233445566:role/GarudaK8sClusterAdminRole",
                account_id="ACC-AWS-PROD-01",
                is_privileged=True,
                permissions=["eks:*", "ec2:Describe*", "iam:PassRole"],
            ),
            CloudIAMRole(
                role_id="ROLE-MTA-WORKLOAD-01",
                role_name="MTAWorkloadRuntimeRole",
                arn_or_uri="arn:aws:iam::112233445566:role/MTAWorkloadRuntimeRole",
                account_id="ACC-AWS-PROD-01",
                is_privileged=False,
                permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt"],
            ),
            CloudIAMRole(
                role_id="ROLE-SECOPS-READONLY-01",
                role_name="SecOpsSecurityAuditRole",
                arn_or_uri="arn:aws:iam::112233445566:role/SecOpsSecurityAuditRole",
                account_id="ACC-AWS-PROD-01",
                is_privileged=False,
                permissions=["securityhub:Get*", "guardduty:List*", "cloudtrail:LookupEvents"],
            ),
        ]
        for r in defaults:
            self._roles[r.role_id] = r

    def get(self, role_id: str) -> Optional[CloudIAMRole]:
        return self._roles.get(role_id)

    def list_all(self) -> List[CloudIAMRole]:
        return list(self._roles.values())

    def register(self, role: CloudIAMRole) -> None:
        self._roles[role.role_id] = role
