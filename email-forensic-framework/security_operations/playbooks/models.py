"""
Phase 25 — SOAR Response Playbooks Base Models & Engine
Defines versioned playbooks, execution steps, approval gates, verification, and rollbacks.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class PlaybookStep:
    step_id: str
    name: str
    action_type: str
    required_approval: bool = False
    is_reversible: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityPlaybook:
    playbook_id: str
    name: str
    version: str
    trigger_event: str
    description: str
    required_autonomy_level: int = 2
    steps: List[PlaybookStep] = field(default_factory=list)
    verification_checks: List[str] = field(default_factory=list)
    rollback_steps: List[PlaybookStep] = field(default_factory=list)


class PlaybookRegistry:
    """Stores and retrieves versioned SOAR response playbooks."""

    def __init__(self):
        self._playbooks: Dict[str, SecurityPlaybook] = {}
        self.register_defaults()

    def register(self, playbook: SecurityPlaybook):
        self._playbooks[playbook.playbook_id] = playbook

    def get(self, playbook_id: str) -> Optional[SecurityPlaybook]:
        return self._playbooks.get(playbook_id)

    def find_by_trigger(self, event_type: str) -> Optional[SecurityPlaybook]:
        evt_lower = event_type.lower()
        for pb in self._playbooks.values():
            if pb.trigger_event.lower() in evt_lower or evt_lower in pb.trigger_event.lower():
                return pb
        return self._playbooks.get("PLAYBOOK-001")

    def list_playbooks(self) -> List[SecurityPlaybook]:
        return list(self._playbooks.values())

    def register_defaults(self):
        # 1. PLAYBOOK-001: TLS Downgrade
        self.register(SecurityPlaybook(
            playbook_id="PLAYBOOK-001",
            name="TLS Downgrade Remediation",
            version="1.2.0",
            trigger_event="tls_downgrade",
            description="Isolates legacy TLS traffic, requests MTA config update, and monitors zero sessions.",
            required_autonomy_level=2,
            steps=[
                PlaybookStep("S1", "Preserve Network Telemetry", "PRESERVE_EVIDENCE", False),
                PlaybookStep("S2", "Simulate Disabling TLS1.0/1.1", "SIMULATE_CHANGE", False),
                PlaybookStep("S3", "Disable Legacy Protocols on Canary MTA", "DISABLE_LEGACY_TLS", True),
                PlaybookStep("S4", "Verify Wire Telemetry", "VERIFY_TELEMETRY", False),
            ],
            verification_checks=["ZERO_LEGACY_TLS_SESSIONS", "MTA_QUEUE_HEALTH"],
            rollback_steps=[PlaybookStep("R1", "Revert MTA Configuration", "RESTORE_CONFIG_SNAPSHOT", False)],
        ))

        # 2. PLAYBOOK-002: Certificate Anomaly
        self.register(SecurityPlaybook(
            playbook_id="PLAYBOOK-002",
            name="Certificate Anomaly Response",
            version="2.0.0",
            trigger_event="certificate_change",
            description="Investigates untrusted or unexpected certificates, revokes rogue certs, and triggers rotation.",
            required_autonomy_level=2,
            steps=[
                PlaybookStep("S1", "Snapshot Existing Certificate Chain", "SNAPSHOT_CERT", False),
                PlaybookStep("S2", "Check Active ITSM Change Tickets", "CHECK_CHANGE_TICKET", False),
                PlaybookStep("S3", "Deploy Verified CA Certificate", "ROTATE_CERTIFICATE", True),
                PlaybookStep("S4", "Verify Handshake Validation", "VERIFY_CERT_HANDSHAKE", False),
            ],
            verification_checks=["VALID_TRUST_CHAIN", "ZERO_UNTRUSTED_HANDSHAKES"],
            rollback_steps=[PlaybookStep("R1", "Restore Prior Certificate", "RESTORE_CERT_SNAPSHOT", True)],
        ))

        # 3. PLAYBOOK-003: Unknown JA4
        self.register(SecurityPlaybook(
            playbook_id="PLAYBOOK-003",
            name="Rare JA4 Threat Containment",
            version="1.0.1",
            trigger_event="new_ja4",
            description="Applies temporary 30-minute quarantine to rare client JA4 fingerprints.",
            required_autonomy_level=3,
            steps=[
                PlaybookStep("S1", "Query JA4 Threat Intel", "ENRICH_JA4", False),
                PlaybookStep("S2", "Apply Bounded JA4 Firewall Quarantine", "QUARANTINE_JA4", False),
                PlaybookStep("S3", "Monitor Recurrence", "START_MONITORING", False),
            ],
            verification_checks=["JA4_BLOCKED_ON_INGRESS"],
            rollback_steps=[PlaybookStep("R1", "Remove JA4 Quarantine Filter", "UNBLOCK_JA4", False)],
        ))

        # 4. PLAYBOOK-006: High-Risk Crypto Regression
        self.register(SecurityPlaybook(
            playbook_id="PLAYBOOK-006",
            name="High-Risk Crypto Regression Response",
            version="3.1.0",
            trigger_event="crypto_regression",
            description="Handles recurring cryptographic regressions with canary rollout and mandatory four-eyes approval.",
            required_autonomy_level=2,
            steps=[
                PlaybookStep("S1", "Preserve Evidence Bundle", "PRESERVE_EVIDENCE", False),
                PlaybookStep("S2", "Calculate Blast Radius", "CALCULATE_BLAST_RADIUS", False),
                PlaybookStep("S3", "Request Senior / Four-Eyes Approval", "REQUEST_APPROVAL", True),
                PlaybookStep("S4", "Deploy Canary Configuration", "CANARY_REMEDIATION", True),
                PlaybookStep("S5", "Verify Passive Telemetry", "VERIFY_TELEMETRY", False),
            ],
            verification_checks=["ZERO_REGRESSION_SESSIONS", "CANARY_HEALTH_PASS"],
            rollback_steps=[PlaybookStep("R1", "Rollback Canary Fleet", "ROLLBACK_CANARY", True)],
        ))
