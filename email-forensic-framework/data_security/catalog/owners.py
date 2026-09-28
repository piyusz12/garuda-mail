"""
Data Ownership and Stewardship Registry.
Components 29.5 & 29.6: Business owner, technical owner, security owner, and steward assignments.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class DataOwnershipAssignment:
    asset_id: str
    business_owner: str
    technical_owner: str
    security_owner: str
    data_steward: str
    last_reviewed_at: float = field(default_factory=time.time)
    review_cadence_days: int = 90

    def is_review_due(self) -> bool:
        return (time.time() - self.last_reviewed_at) > (self.review_cadence_days * 86400)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "business_owner": self.business_owner,
            "technical_owner": self.technical_owner,
            "security_owner": self.security_owner,
            "data_steward": self.data_steward,
            "last_reviewed_at": self.last_reviewed_at,
            "review_cadence_days": self.review_cadence_days,
            "is_review_due": self.is_review_due(),
        }


class DataOwnershipRegistry:
    """Manages ownership accountability and stewardship reviews across data assets."""

    def __init__(self):
        self._assignments: Dict[str, DataOwnershipAssignment] = {}
        self._seed_defaults()

    def _seed_defaults(self):
        self.assign_ownership(
            asset_id="DATA-8821",
            business_owner="customer-platform",
            technical_owner="database-team",
            security_owner="security-team",
            data_steward="steward-compliance@garuda.enterprise",
        )

    def assign_ownership(
        self,
        asset_id: str,
        business_owner: str,
        technical_owner: str,
        security_owner: str,
        data_steward: str,
    ) -> DataOwnershipAssignment:
        assignment = DataOwnershipAssignment(
            asset_id=asset_id,
            business_owner=business_owner,
            technical_owner=technical_owner,
            security_owner=security_owner,
            data_steward=data_steward,
        )
        self._assignments[asset_id] = assignment
        return assignment

    def get_ownership(self, asset_id: str) -> Optional[DataOwnershipAssignment]:
        return self._assignments.get(asset_id)

    def list_unowned_assets(self, all_asset_ids: List[str]) -> List[str]:
        return [aid for aid in all_asset_ids if aid not in self._assignments]
