"""
Data Loss Prevention (DLP) Policies.
Component 29.30 & 29.37: Evaluates identity, workload, data classification, volume, and destination context.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import time

from data_security.dlp.decisions import DLPAction
from data_security.inventory.normalization import ClassificationLevel


@dataclass
class DLPPolicy:
    policy_id: str
    name: str
    target_classifications: List[ClassificationLevel]
    action: DLPAction
    prohibit_external: bool = True
    max_record_limit: int = 50000
    exempt_identities: List[str] = field(default_factory=list)
    is_active: bool = True

    def evaluate(self, flow: Dict[str, Any]) -> Tuple[bool, str]:
        """Returns (is_violated, reason)."""
        if not self.is_active:
            return False, ""

        flow_class_str = str(flow.get("classification", "INTERNAL"))
        matches_class = any(
            flow_class_str == (c.value if isinstance(c, ClassificationLevel) else str(c))
            for c in self.target_classifications
        )
        if not matches_class:
            return False, ""

        identity = flow.get("identity_id", "")
        if identity in self.exempt_identities:
            return False, ""

        # 1. Prohibit external transfer check
        is_external = flow.get("is_external_destination", False) or "external" in str(flow.get("destination_id", "")).lower()
        if self.prohibit_external and is_external:
            return True, f"Policy {self.policy_id}: Transfer of {flow_class_str} data to unapproved external destination {flow.get('destination_id')} is prohibited."

        # 2. Volume threshold check
        records = flow.get("record_count", 0)
        if records > self.max_record_limit:
            return True, f"Policy {self.policy_id}: Transfer volume of {records:,} records exceeds maximum allowed threshold of {self.max_record_limit:,}."

        return False, ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "target_classifications": [c.value if isinstance(c, ClassificationLevel) else str(c) for c in self.target_classifications],
            "action": self.action.value,
            "prohibit_external": self.prohibit_external,
            "max_record_limit": self.max_record_limit,
            "exempt_identities": self.exempt_identities,
            "is_active": self.is_active,
        }
