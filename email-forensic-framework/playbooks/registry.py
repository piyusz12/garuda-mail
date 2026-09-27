"""
Phase 24 — Playbook Registry (Components 4, 8, 9)
Pre-loads standardized enterprise cryptographic and email forensic response procedures.
"""

from typing import Dict, List, Optional
from playbooks.models import Playbook, PlaybookStep, PlaybookMaturity


class PlaybookRegistry:
    """Enterprise repository of standardized operational response procedures."""

    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {}
        self._load_standard_playbooks()

    def _load_standard_playbooks(self):
        # 1. CRYPTO-REGRESSION-001 (Section 24.9)
        self.playbooks["CRYPTO-REGRESSION-001"] = Playbook(
            playbook_id="CRYPTO-REGRESSION-001",
            name="Legacy TLS Recurrence After Remediation",
            version="2.1",
            maturity=PlaybookMaturity.CANARY_AUTOMATION,
            trigger="DET-TLS-001",
            preconditions=["Active network telemetry indicates TLS 1.0 or TLS 1.1 sessions on remediated MTA"],
            investigation_steps=[
                PlaybookStep("INV-01", 1, "Identify affected assets", "INVESTIGATION", "query_affected_assets", "Scan lakehouse for all assets running deprecated TLS versions."),
                PlaybookStep("INV-02", 2, "Determine first recurrence", "INVESTIGATION", "check_first_recurrence", "Correlate historical lakehouse sessions to isolate regression timestamp."),
                PlaybookStep("INV-03", 3, "Check approved change requests", "INVESTIGATION", "check_change_management", "Determine if change was operator error or unauthorized drift."),
            ],
            containment_steps=[
                PlaybookStep("CNT-01", 1, "Quarantine legacy cipher suite", "CONTAINMENT", "quarantine_cipher", "Temporarily rate limit or quarantine legacy TLS handshakes.", required_approval=False),
            ],
            remediation_steps=[
                PlaybookStep("REM-01", 1, "Simulate TLS 1.1 disablement", "REMEDIATION", "simulate_change", "Run digital twin compatibility assessment.", required_approval=False),
                PlaybookStep("REM-02", 2, "Disable TLS 1.0 and TLS 1.1 on MTA", "REMEDIATION", "mta_disable_legacy_tls", "Enforce TLS 1.2+ and AEAD ciphers in MTA configuration.", required_approval=True),
            ],
            verification_steps=[
                PlaybookStep("VER-01", 1, "Verify with passive telemetry", "VERIFICATION", "verify_passive_telemetry", "Confirm zero TLS 1.0/1.1 sessions over minimum 30 minute observation window."),
            ],
            rollback_steps=[
                PlaybookStep("RBK-01", 1, "Re-enable TLS 1.0/1.1", "ROLLBACK", "mta_enable_legacy_tls", "Restore previous daemon configuration snapshot."),
            ],
            closure_conditions=[
                "Remediation verified with zero observed legacy sessions",
                "Monitoring active for 24h with no recurrence",
                "Root-cause documented in lessons learned"
            ],
            historical_rollback_rate=0.02,
            execution_count=48
        )

        # 2. CERT-COMPROMISE-002
        self.playbooks["CERT-COMPROMISE-002"] = Playbook(
            playbook_id="CERT-COMPROMISE-002",
            name="Suspected Private Key or Certificate Compromise",
            version="1.4",
            maturity=PlaybookMaturity.APPROVAL_DRIVEN,
            trigger="DET-CERT-003",
            preconditions=["Certificate thumbprint seen on rogue external IP or unauthorized subject alt name"],
            investigation_steps=[
                PlaybookStep("INV-01", 1, "Extract certificate thumbprint & chain", "INVESTIGATION", "inspect_cert_chain", "Verify issuer, serial, and public key parameters."),
                PlaybookStep("INV-02", 2, "Enumerate dependent MTAs", "INVESTIGATION", "map_cert_dependencies", "Identify all servers and load balancers serving this certificate."),
            ],
            containment_steps=[
                PlaybookStep("CNT-01", 1, "Prepare emergency replacement certificate", "CONTAINMENT", "request_emergency_cert", "Generate replacement CSR with high-assurance CA.", required_approval=True),
            ],
            remediation_steps=[
                PlaybookStep("REM-01", 1, "Deploy replacement certificate", "REMEDIATION", "deploy_certificate", "Update keystore across all affected MTA endpoints.", required_approval=True),
                PlaybookStep("REM-02", 2, "Revoke compromised certificate", "REMEDIATION", "revoke_certificate", "Submit CRL / OCSP revocation notice to issuing CA.", required_approval=True),
            ],
            verification_steps=[
                PlaybookStep("VER-01", 1, "Verify replacement certificate in telemetry", "VERIFICATION", "verify_certificate_telemetry", "Ensure new serial number is observed on all incoming Client/ServerHellos."),
            ],
            rollback_steps=[
                PlaybookStep("RBK-01", 1, "Revert keystore to backup cert", "ROLLBACK", "restore_backup_keystore", "Reinstall previous cert if replacement has negotiation incompatibilities."),
            ],
            closure_conditions=["Revocation confirmed via OCSP", "New cert active across 100% of flows"],
            historical_rollback_rate=0.05,
            execution_count=19
        )

        # 3. LEGACY-EXPOSURE-004 (STARTTLS Stripping / Plaintext Auth)
        self.playbooks["LEGACY-EXPOSURE-004"] = Playbook(
            playbook_id="LEGACY-EXPOSURE-004",
            name="STARTTLS Stripping & Cleartext Credential Exposure",
            version="2.0",
            maturity=PlaybookMaturity.CANARY_AUTOMATION,
            trigger="DET-AUTH-003",
            preconditions=["Plaintext AUTH credentials observed following STARTTLS rejection or stripping"],
            investigation_steps=[
                PlaybookStep("INV-01", 1, "Inspect STARTTLS handshake timeline", "INVESTIGATION", "inspect_starttls_timeline", "Verify whether downgrade occurred due to MITM injection or server misconfiguration."),
            ],
            containment_steps=[
                PlaybookStep("CNT-01", 1, "Quarantine plain authentication on port 25", "CONTAINMENT", "block_plain_auth", "Block AUTH commands over unencrypted connections.", required_approval=False),
            ],
            remediation_steps=[
                PlaybookStep("REM-01", 1, "Enforce mandatory STARTTLS (smtpd_tls_security_level=encrypt)", "REMEDIATION", "mta_enforce_mandatory_starttls", "Reject any unencrypted command attempts.", required_approval=True),
            ],
            verification_steps=[
                PlaybookStep("VER-01", 1, "Verify zero cleartext credentials", "VERIFICATION", "verify_zero_cleartext_auth", "Observe passive telemetry to verify 100% encrypted authentication."),
            ],
            rollback_steps=[
                PlaybookStep("RBK-01", 1, "Restore opportunistic STARTTLS", "ROLLBACK", "mta_restore_opportunistic_tls", "Revert smtpd_tls_security_level to may."),
            ],
            closure_conditions=["Zero cleartext AUTH attempts for 48 hours", "Mandatory STARTTLS active"],
            historical_rollback_rate=0.01,
            execution_count=35
        )

        # 4. SUSPICIOUS-JA4-005 (Rogue Client Fingerprint)
        self.playbooks["SUSPICIOUS-JA4-005"] = Playbook(
            playbook_id="SUSPICIOUS-JA4-005",
            name="Rogue JA4+ Fingerprint / C2 Beaconing",
            version="1.2",
            maturity=PlaybookMaturity.APPROVAL_DRIVEN,
            trigger="DET-JA4-004",
            preconditions=["ClientHello matches known exploit framework or malware JA4 fingerprint"],
            investigation_steps=[
                PlaybookStep("INV-01", 1, "Correlate JA4 source IP & host", "INVESTIGATION", "correlate_ja4_source", "Identify client origin and connection periodicity."),
            ],
            containment_steps=[
                PlaybookStep("CNT-01", 1, "Temporary 30-minute firewall ACL block", "CONTAINMENT", "firewall_block_ja4", "Block connection source with automated re-evaluation.", required_approval=False),
            ],
            remediation_steps=[
                PlaybookStep("REM-01", 1, "Permanent network firewall ACL rule", "REMEDIATION", "firewall_add_permanent_acl", "Add permanent block on threat actor CIDR.", required_approval=True),
            ],
            verification_steps=[
                PlaybookStep("VER-01", 1, "Confirm zero incoming packets from blocked JA4", "VERIFICATION", "verify_traffic_dropped", "Verify firewall drop counters incrementing and zero sessions established."),
            ],
            rollback_steps=[
                PlaybookStep("RBK-01", 1, "Remove firewall ACL rule", "ROLLBACK", "firewall_remove_acl", "Restore client access if false positive confirmed."),
            ],
            closure_conditions=["Rogue traffic eliminated", "Incident reviewed by SOC analyst"],
            historical_rollback_rate=0.03,
            execution_count=62
        )

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def match_playbook_for_trigger(self, trigger_rule_or_title: str) -> Optional[Playbook]:
        """Finds the most suitable playbook based on detection rule ID or title keywords."""
        for p in self.playbooks.values():
            if p.trigger.lower() in trigger_rule_or_title.lower() or p.playbook_id.lower() in trigger_rule_or_title.lower():
                return p
        if "TLS" in trigger_rule_or_title.upper() or "DOWNGRADE" in trigger_rule_or_title.upper():
            return self.playbooks.get("CRYPTO-REGRESSION-001")
        if "CERT" in trigger_rule_or_title.upper():
            return self.playbooks.get("CERT-COMPROMISE-002")
        if "JA4" in trigger_rule_or_title.upper():
            return self.playbooks.get("SUSPICIOUS-JA4-005")
        if "AUTH" in trigger_rule_or_title.upper() or "STRIP" in trigger_rule_or_title.upper():
            return self.playbooks.get("LEGACY-EXPOSURE-004")
        return self.playbooks.get("CRYPTO-REGRESSION-001")
