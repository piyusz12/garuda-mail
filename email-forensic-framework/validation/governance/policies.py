"""
Validation Governance Policies & Blast Radius Guardrails.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class GovernancePolicy:
    policy_id: str
    name: str
    description: str
    require_two_person_rule_for_high_risk: bool = True
    enforce_mandatory_rollback_snapshot: bool = True
    allowed_operating_hours_utc: str = "00:00-23:59"
    max_active_scenarios_per_range: int = 1
    evidence_retention_days: int = 365

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "require_two_person_rule_for_high_risk": self.require_two_person_rule_for_high_risk,
            "enforce_mandatory_rollback_snapshot": self.enforce_mandatory_rollback_snapshot,
            "allowed_operating_hours_utc": self.allowed_operating_hours_utc,
            "max_active_scenarios_per_range": self.max_active_scenarios_per_range,
            "evidence_retention_days": self.evidence_retention_days,
        }
