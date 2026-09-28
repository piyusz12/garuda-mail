"""
Data Retention Policies and Legal Hold Controls.
Component 29.25: Manages dataset lifespan, legal hold exemptions, and compliant archiving rules.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class DataRetentionPolicy:
    policy_id: str
    name: str
    target_data_domain: str  # Customer, Financial, Forensics, Logs
    retention_period_days: int
    is_legal_hold_exempt: bool = False
    auto_deletion_enabled: bool = False
    archive_after_days: int = 180
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "target_data_domain": self.target_data_domain,
            "retention_period_days": self.retention_period_days,
            "is_legal_hold_exempt": self.is_legal_hold_exempt,
            "auto_deletion_enabled": self.auto_deletion_enabled,
            "archive_after_days": self.archive_after_days,
            "created_at": self.created_at,
        }
