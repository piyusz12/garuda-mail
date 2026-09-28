"""
Phase 24 — Action Risk Classification (Component 41)
R0: Read-only
R1: Non-disruptive
R2: Limited reversible
R3: Potential service impact
R4: Major / critical change
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any


class ActionRiskClass(str, Enum):
    R0 = "R0"  # Read-only (e.g., query lakehouse, export pcap evidence)
    R1 = "R1"  # Non-disruptive (e.g., alert SOC, update ticket, add tag)
    R2 = "R2"  # Limited reversible (e.g., temporary rate limit, test config change)
    R3 = "R3"  # Potential service impact (e.g., disable cipher suite, restart MTA daemon)
    R4 = "R4"  # Major / critical change (e.g., isolate host, revoke root cert, global protocol disable)


@dataclass
class RiskProfile:
    risk_class: ActionRiskClass
    name: str
    description: str
    default_approval_required: bool
    requires_four_eyes: bool
    requires_simulation: bool
    requires_rollback_plan: bool


RISK_PROFILES: Dict[ActionRiskClass, RiskProfile] = {
    ActionRiskClass.R0: RiskProfile(
        risk_class=ActionRiskClass.R0,
        name="Read-Only",
        description="Non-mutating diagnostic, queries, and evidence extraction.",
        default_approval_required=False,
        requires_four_eyes=False,
        requires_simulation=False,
        requires_rollback_plan=False,
    ),
    ActionRiskClass.R1: RiskProfile(
        risk_class=ActionRiskClass.R1,
        name="Non-Disruptive",
        description="Configuration tagging, notifications, ticketing, and passive metrics.",
        default_approval_required=False,
        requires_four_eyes=False,
        requires_simulation=False,
        requires_rollback_plan=False,
    ),
    ActionRiskClass.R2: RiskProfile(
        risk_class=ActionRiskClass.R2,
        name="Limited Reversible",
        description="Temporary rate limiting, canary ACL adjustments, and soft quarantines.",
        default_approval_required=False,
        requires_four_eyes=False,
        requires_simulation=True,
        requires_rollback_plan=True,
    ),
    ActionRiskClass.R3: RiskProfile(
        risk_class=ActionRiskClass.R3,
        name="Potential Service Impact",
        description="Disabling legacy cipher suites, intermediate cert rotation, protocol toggles.",
        default_approval_required=True,
        requires_four_eyes=False,
        requires_simulation=True,
        requires_rollback_plan=True,
    ),
    ActionRiskClass.R4: RiskProfile(
        risk_class=ActionRiskClass.R4,
        name="Major / Critical Change",
        description="Network isolation, root CA revocation, emergency MTA shutdown, global protocol disablement.",
        default_approval_required=True,
        requires_four_eyes=True,
        requires_simulation=True,
        requires_rollback_plan=True,
    ),
}
