"""
Phase 25 — Detection Engineering Rule Models & Repository
Manages versioned Detection-as-Code definitions and change records.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class DetectionRuleDefinition:
    rule_id: str
    name: str
    version: str
    severity: str
    target_event: str
    description: str
    query_dsl: str
    enabled: bool = True
    canary_ratio: float = 1.0  # 1.0 = full production, 0.1 = canary
    parameters: Dict[str, Any] = field(default_factory=dict)
    change_history: List[Dict[str, Any]] = field(default_factory=list)


class DetectionRuleRepository:
    """Stores versioned detection rules with change management tracking."""

    def __init__(self):
        self._rules: Dict[str, DetectionRuleDefinition] = {}
        self.register_defaults()

    def register_defaults(self):
        self._rules["TLS-LEGACY-001"] = DetectionRuleDefinition(
            rule_id="TLS-LEGACY-001",
            name="Legacy TLS Protocol Ingress",
            version="3.1.0",
            severity="HIGH",
            target_event="tls_downgrade",
            description="Detects TLS 1.0 or TLS 1.1 sessions active on inbound or outbound MTAs.",
            query_dsl="EVENT == 'tls_session' AND protocol_version IN ['TLSv1.0', 'TLSv1.1']",
        )
        self._rules["CERT-ROTATION-002"] = DetectionRuleDefinition(
            rule_id="CERT-ROTATION-002",
            name="Untrusted Certificate Thumbprint",
            version="2.0.0",
            severity="CRITICAL",
            target_event="certificate_change",
            description="Flags newly presented server certificates lacking valid trust chain.",
            query_dsl="EVENT == 'cert_presented' AND trust_chain_valid == False",
        )
        self._rules["JA4-ANOMALY-003"] = DetectionRuleDefinition(
            rule_id="JA4-ANOMALY-003",
            name="Rare JA4 Client Ingress Signature",
            version="1.1.0",
            severity="MEDIUM",
            target_event="new_ja4",
            description="Identifies client JA4 fingerprints with frequency < 3 in the past 90 days.",
            query_dsl="EVENT == 'client_hello' AND ja4_frequency_90d < 3",
        )

    def get_rule(self, rule_id: str) -> Optional[DetectionRuleDefinition]:
        return self._rules.get(rule_id)

    def update_rule(
        self,
        rule_id: str,
        new_version: str,
        reason: str,
        author: str,
        updated_dsl: Optional[str] = None,
        canary_ratio: float = 1.0,
    ) -> DetectionRuleDefinition:
        rule = self._rules.get(rule_id)
        if not rule:
            raise KeyError(f"Rule '{rule_id}' not found.")

        change_record = {
            "from_version": rule.version,
            "to_version": new_version,
            "reason": reason,
            "author": author,
            "timestamp": time.time(),
        }
        rule.version = new_version
        rule.canary_ratio = canary_ratio
        if updated_dsl:
            rule.query_dsl = updated_dsl
        rule.change_history.append(change_record)
        return rule

    def list_rules(self) -> List[DetectionRuleDefinition]:
        return list(self._rules.values())
