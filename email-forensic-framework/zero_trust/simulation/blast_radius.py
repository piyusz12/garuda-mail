"""
Policy Change Blast Radius Calculator.
Component 84: Analyzes the scope of identities, devices, and services affected before deploying a policy modification.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

from zero_trust.policy.parser import ZeroTrustPolicy
from identity.ingestion.users import UserIdentityRepository
from identity.ingestion.devices import DeviceIdentityRepository
from identity.ingestion.services import ServiceIdentityRepository


@dataclass
class PolicyBlastRadiusAssessment:
    policy_id: str
    affected_identities_count: int
    affected_devices_count: int
    affected_services_count: int
    affected_identity_ids: List[str]
    affected_service_ids: List[str]
    risk_classification: str  # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "affected_identities_count": self.affected_identities_count,
            "affected_devices_count": self.affected_devices_count,
            "affected_services_count": self.affected_services_count,
            "affected_identity_ids": self.affected_identity_ids,
            "affected_service_ids": self.affected_service_ids,
            "risk_classification": self.risk_classification,
        }


class PolicyBlastRadiusAnalyzer:
    """Calculates fleet impact for proposed policy modifications."""

    def __init__(
        self,
        user_repo: UserIdentityRepository,
        device_repo: DeviceIdentityRepository,
        service_repo: ServiceIdentityRepository,
    ):
        self.user_repo = user_repo
        self.device_repo = device_repo
        self.service_repo = service_repo

    def evaluate_blast_radius(self, policy: ZeroTrustPolicy) -> PolicyBlastRadiusAssessment:
        all_users = self.user_repo.list_all()
        all_devices = self.device_repo.list_all()
        all_services = self.service_repo.list_all()

        # Match services
        if "*" in policy.target_services:
            matched_services = all_services
        else:
            matched_services = [s for s in all_services if s.service_id in policy.target_services]

        # Match users by group condition if present
        matched_users = []
        group_filter = None
        for c in policy.conditions:
            if c.attribute == "subject.group":
                group_filter = c.value
                break

        if group_filter:
            matched_users = [u for u in all_users if group_filter in u.groups]
        else:
            matched_users = all_users

        # Match associated devices
        user_ids = set(u.identity_id for u in matched_users)
        matched_devices = [d for d in all_devices if d.owner_identity_id in user_ids]

        u_count = len(matched_users)
        s_count = len(matched_services)

        risk = "LOW"
        if u_count > 500 or s_count > 10:
            risk = "CRITICAL"
        elif u_count > 100 or s_count > 3:
            risk = "HIGH"
        elif u_count > 10 or s_count > 1:
            risk = "MEDIUM"

        return PolicyBlastRadiusAssessment(
            policy_id=policy.policy_id,
            affected_identities_count=u_count,
            affected_devices_count=len(matched_devices),
            affected_services_count=s_count,
            affected_identity_ids=[u.identity_id for u in matched_users],
            affected_service_ids=[s.service_id for s in matched_services],
            risk_classification=risk,
        )
