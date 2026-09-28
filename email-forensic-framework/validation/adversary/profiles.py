"""
Validation Adversary Profiles.
Structured representation of adversaries, objectives, entry conditions, and behaviors.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid
import time


class AdversaryTier(str, Enum):
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    COMMERCIAL_MALWARE = "COMMERCIAL_MALWARE"
    CYBERCRIME_GROUP = "CYBERCRIME_GROUP"
    INSIDER_THREAT = "INSIDER_THREAT"
    APT_STATE_SPONSORED = "APT_STATE_SPONSORED"


class ThreatObjective(str, Enum):
    GAIN_ACCESS = "gain_access"
    MOVE_LATERALLY = "move_laterally"
    CREDENTIAL_ACCESS = "credential_access"
    DOWNGRADE_CRYPTO = "downgrade_crypto"
    SUBSTITUTE_CERTIFICATE = "substitute_certificate"
    EXFILTRATE_DATA = "exfiltrate_data"
    EVADE_DETECTION = "evade_detection"
    DISRUPT_SERVICE = "disrupt_service"


@dataclass
class AdversaryProfile:
    profile_id: str
    name: str
    tier: AdversaryTier
    description: str
    objectives: List[ThreatObjective]
    entry_conditions: List[str]
    technique_ids: List[str]
    infrastructure_types: List[str]
    behaviors: List[str]
    persistence_patterns: List[str]
    expected_artifacts: List[str]
    risk_level: str = "HIGH"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "tier": self.tier.value if isinstance(self.tier, AdversaryTier) else self.tier,
            "description": self.description,
            "objectives": [obj.value if isinstance(obj, ThreatObjective) else obj for obj in self.objectives],
            "entry_conditions": self.entry_conditions,
            "technique_ids": self.technique_ids,
            "infrastructure_types": self.infrastructure_types,
            "behaviors": self.behaviors,
            "persistence_patterns": self.persistence_patterns,
            "expected_artifacts": self.expected_artifacts,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
        }


class AdversaryProfileRepository:
    """Repository of standard adversarial profiles for defensive validation."""

    def __init__(self):
        self._profiles: Dict[str, AdversaryProfile] = {}
        self._load_default_profiles()

    def _load_default_profiles(self):
        defaults = [
            AdversaryProfile(
                profile_id="ADV-001",
                name="Legacy TLS & Crypto Downgrader",
                tier=AdversaryTier.CYBERCRIME_GROUP,
                description="Simulates adversary attempting to force legacy TLS 1.0/1.1 or weak ciphers to eavesdrop on SMTP STARTTLS.",
                objectives=[ThreatObjective.DOWNGRADE_CRYPTO, ThreatObjective.EXFILTRATE_DATA],
                entry_conditions=["network_man_in_the_middle", "mta_edge_exposure"],
                technique_ids=["TECH-TLS-001", "TECH-TLS-002", "TECH-STARTTLS-001"],
                infrastructure_types=["proxy_relay", "rogue_dns"],
                behaviors=["protocol_downgrade", "tls_fallback_forcing", "cipher_tampering"],
                persistence_patterns=["periodic_retry"],
                expected_artifacts=["tls_client_hello", "downgrade_alert", "weak_cipher_negotiation"],
                risk_level="MEDIUM",
            ),
            AdversaryProfile(
                profile_id="ADV-002",
                name="Rogue Certificate & Key Impersonator",
                tier=AdversaryTier.APT_STATE_SPONSORED,
                description="Simulates sophisticated actor presenting rogue, self-signed, or swapped certificates to intercept mail traffic.",
                objectives=[ThreatObjective.SUBSTITUTE_CERTIFICATE, ThreatObjective.GAIN_ACCESS],
                entry_conditions=["dns_hijack", "internal_pivot"],
                technique_ids=["TECH-CERT-001", "TECH-CERT-002", "TECH-CERT-003"],
                infrastructure_types=["untrusted_ca", "shadow_mta"],
                behaviors=["cert_chain_substitution", "self_signed_impersonation", "expired_cert_usage"],
                persistence_patterns=["certificate_pinning_bypass"],
                expected_artifacts=["x509_certificate_event", "untrusted_issuer_alert", "chain_mismatch"],
                risk_level="CRITICAL",
            ),
            AdversaryProfile(
                profile_id="ADV-003",
                name="Stealth JA4 Anomaly Lateral Movement",
                tier=AdversaryTier.APT_STATE_SPONSORED,
                description="Simulates adversary moving laterally between MTAs using unapproved mail clients and anomalous JA4 TLS fingerprints.",
                objectives=[ThreatObjective.MOVE_LATERALLY, ThreatObjective.EVADE_DETECTION],
                entry_conditions=["compromised_mta_credentials"],
                technique_ids=["TECH-JA4-001", "TECH-JA4-002", "TECH-LATERAL-001"],
                infrastructure_types=["compromised_internal_host"],
                behaviors=["anomalous_ja4_fingerprint", "rare_tls_extension", "unusual_destination_port"],
                persistence_patterns=["beaconing_mta"],
                expected_artifacts=["ja4_fingerprint_record", "client_hello_signature", "session_frequency_spike"],
                risk_level="HIGH",
            ),
            AdversaryProfile(
                profile_id="ADV-004",
                name="Credential Harvesting & STARTTLS Stripper",
                tier=AdversaryTier.COMMERCIAL_MALWARE,
                description="Simulates stripped STARTTLS commands followed by plaintext SMTP authentication credential harvesting.",
                objectives=[ThreatObjective.CREDENTIAL_ACCESS, ThreatObjective.DOWNGRADE_CRYPTO],
                entry_conditions=["inline_network_tap"],
                technique_ids=["TECH-STARTTLS-002", "TECH-CRED-001"],
                infrastructure_types=["traffic_interceptor"],
                behaviors=["starttls_command_tampering", "plaintext_auth_capture"],
                persistence_patterns=["passive_snoop"],
                expected_artifacts=["smtp_starttls_rejected", "plaintext_auth_warning"],
                risk_level="CRITICAL",
            ),
            AdversaryProfile(
                profile_id="ADV-005",
                name="Post-Quantum Cryptographic Regression",
                tier=AdversaryTier.CYBERCRIME_GROUP,
                description="Simulates an environment where quantum-resistant algorithms (ML-KEM, Kyber) are degraded to classical crypto.",
                objectives=[ThreatObjective.DOWNGRADE_CRYPTO],
                entry_conditions=["mta_configuration_tamper"],
                technique_ids=["TECH-CRYPTO-PQC-001"],
                infrastructure_types=["mta_agent"],
                behaviors=["pqc_key_share_stripping", "classical_only_kex"],
                persistence_patterns=["config_override"],
                expected_artifacts=["pqc_hybrid_downgrade", "crypto_inventory_violation"],
                risk_level="HIGH",
            )
        ]
        for p in defaults:
            self._profiles[p.profile_id] = p

    def get(self, profile_id: str) -> Optional[AdversaryProfile]:
        return self._profiles.get(profile_id)

    def list_all(self) -> List[AdversaryProfile]:
        return list(self._profiles.values())

    def register(self, profile: AdversaryProfile) -> None:
        self._profiles[profile.profile_id] = profile
