"""
Data Retention Expiry Auditor.
Component 29.25: Identifies stale or overdue sensitive datasets violating retention periods.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from data_security.inventory.normalization import DataAsset
from data_security.retention.policies import DataRetentionPolicy


@dataclass
class RetentionExpiryFinding:
    asset_id: str
    asset_name: str
    age_days: int
    max_retention_days: int
    overdue_days: int
    is_legal_hold: bool
    action_required: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "age_days": self.age_days,
            "max_retention_days": self.max_retention_days,
            "overdue_days": self.overdue_days,
            "is_legal_hold": self.is_legal_hold,
            "action_required": self.action_required,
        }


class RetentionExpiryAuditor:
    """Audits data assets against their retention lifespans and flags overdue records."""

    def audit_assets(self, assets: List[DataAsset]) -> List[RetentionExpiryFinding]:
        findings: List[RetentionExpiryFinding] = []
        now = time.time()

        for a in assets:
            age_days = int((now - a.created_at) / 86400)
            is_legal_hold = a.tags.get("LegalHold", "false").lower() == "true"

            if not is_legal_hold and age_days > a.retention_days:
                overdue = age_days - a.retention_days
                findings.append(
                    RetentionExpiryFinding(
                        asset_id=a.data_asset_id,
                        asset_name=a.name,
                        age_days=age_days,
                        max_retention_days=a.retention_days,
                        overdue_days=overdue,
                        is_legal_hold=is_legal_hold,
                        action_required="Initiate verified cryptographic deletion or permanent cold archival.",
                    )
                )

        return findings
