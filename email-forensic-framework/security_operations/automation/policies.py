"""
Phase 25 — Response Policy-as-Code
Declarative response policy specifications for autonomous security operations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from .autonomy import AutonomyLevel


@dataclass
class ResponsePolicyRule:
    rule_id: str
    name: str
    target_event: str
    max_risk_for_auto: float
    allowed_autonomy_level: AutonomyLevel
    require_dry_run: bool = True
    require_canary: bool = True
    rollback_on_failure: bool = True


class ResponsePolicyEngine:
    """Evaluates declarative response rules for operational decisions."""

    def __init__(self):
        self.rules: Dict[str, ResponsePolicyRule] = {
            "POL-TLS": ResponsePolicyRule(
                rule_id="POL-TLS",
                name="Legacy TLS Quarantine Policy",
                target_event="tls_downgrade",
                max_risk_for_auto=85.0,
                allowed_autonomy_level=AutonomyLevel.LEVEL_3_LOW_IMPACT,
                require_canary=True,
            ),
            "POL-CERT": ResponsePolicyRule(
                rule_id="POL-CERT",
                name="Certificate Anomaly Policy",
                target_event="certificate_change",
                max_risk_for_auto=90.0,
                allowed_autonomy_level=AutonomyLevel.LEVEL_2_PREPARE,
                require_canary=True,
            ),
            "POL-JA4": ResponsePolicyRule(
                rule_id="POL-JA4",
                name="Rare JA4 Bounded Filter Policy",
                target_event="new_ja4",
                max_risk_for_auto=75.0,
                allowed_autonomy_level=AutonomyLevel.LEVEL_3_LOW_IMPACT,
                require_canary=False,
            ),
        }

    def get_rule(self, event_type: str) -> Optional[ResponsePolicyRule]:
        for r in self.rules.values():
            if r.target_event in event_type.lower():
                return r
        return None
