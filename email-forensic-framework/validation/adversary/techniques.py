"""
Technique Library for Controlled Adversary Emulation & Defensive Validation.
Each technique specifies prerequisites, expected telemetry, detections, response, and safe execution method.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class TechniqueCategory(str, Enum):
    NETWORK = "network"
    CRYPTOGRAPHY = "cryptography"
    CERTIFICATES = "certificates"
    CREDENTIALS = "credentials"
    EVASION = "evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    MAIL_PROTOCOL = "mail_protocol"


class TechniqueRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Technique:
    technique_id: str
    name: str
    category: TechniqueCategory
    risk: TechniqueRisk
    description: str
    prerequisites: List[str]
    expected_telemetry: List[str]
    expected_detections: List[str]
    expected_response: str
    safe_execution_method: str
    mitigation_controls: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "category": self.category.value if isinstance(self.category, TechniqueCategory) else self.category,
            "risk": self.risk.value if isinstance(self.risk, TechniqueRisk) else self.risk,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "expected_telemetry": self.expected_telemetry,
            "expected_detections": self.expected_detections,
            "expected_response": self.expected_response,
            "safe_execution_method": self.safe_execution_method,
            "mitigation_controls": self.mitigation_controls,
            "version": self.version,
            "tags": self.tags,
        }


class TechniqueLibrary:
    """Central repository of adversarial validation techniques."""

    def __init__(self):
        self._techniques: Dict[str, Technique] = {}
        self._load_builtins()

    def _load_builtins(self):
        builtins = [
            Technique(
                technique_id="TECH-042",
                name="Suspicious TLS Behavior & Downgrade Attempt",
                category=TechniqueCategory.NETWORK,
                risk=TechniqueRisk.MEDIUM,
                description="Client initiates TLS handshake requesting legacy TLS 1.0/1.1 protocols or insecure cipher suites.",
                prerequisites=["target_mta_reachable", "tls_sensor_active"],
                expected_telemetry=["tls_event", "ja4_event", "session_event"],
                expected_detections=["TLS-LEGACY-001"],
                expected_response="ISOLATE_HOST",
                safe_execution_method="synthetic_client_hello_emission",
                mitigation_controls=["tls_policy_enforcement", "strict_transport_security"],
                tags=["tls", "downgrade", "network"],
            ),
            Technique(
                technique_id="TECH-CERT-001",
                name="Rogue / Untrusted Certificate Presentation",
                category=TechniqueCategory.CERTIFICATES,
                risk=TechniqueRisk.HIGH,
                description="Simulates presentation of an untrusted, self-signed or unauthorized X.509 certificate on MTA port 25/587.",
                prerequisites=["range_mta_active", "cert_parser_online"],
                expected_telemetry=["certificate_event", "x509_chain_event", "tls_handshake_event"],
                expected_detections=["CERT-CHANGE-001"],
                expected_response="ROTATE_CERTIFICATE",
                safe_execution_method="mock_certificate_rotation_packet",
                mitigation_controls=["mta_sts_policy", "dane_tlsa_enforcement"],
                tags=["certificate", "pki", "crypto"],
            ),
            Technique(
                technique_id="TECH-CERT-002",
                name="Certificate Chain Mismatch & Expired Authority",
                category=TechniqueCategory.CERTIFICATES,
                risk=TechniqueRisk.HIGH,
                description="Presents a certificate whose issuer is untrusted or whose intermediate chain validation fails.",
                prerequisites=["range_mta_active"],
                expected_telemetry=["certificate_event", "chain_validation_error"],
                expected_detections=["CERT-CHAIN-002"],
                expected_response="QUARANTINE_TRAFFIC",
                safe_execution_method="sandboxed_cert_handshake",
                mitigation_controls=["automated_acme_renewal", "ocsp_stapling"],
                tags=["certificate", "chain", "x509"],
            ),
            Technique(
                technique_id="TECH-JA4-001",
                name="Anomalous / Rare JA4 TLS Fingerprint",
                category=TechniqueCategory.NETWORK,
                risk=TechniqueRisk.MEDIUM,
                description="Generates TLS client hello with an anomalous JA4 signature never seen in baseline 90-day mail traffic.",
                prerequisites=["ja4_fingerprinting_sensor"],
                expected_telemetry=["ja4_event", "tls_event"],
                expected_detections=["JA4-ANOMALY-001"],
                expected_response="RATE_LIMIT_IP",
                safe_execution_method="custom_ja4_client_hello_stream",
                mitigation_controls=["ja4_baseline_filtering"],
                tags=["ja4", "fingerprint", "anomaly"],
            ),
            Technique(
                technique_id="TECH-STARTTLS-001",
                name="STARTTLS Stripping Anomaly",
                category=TechniqueCategory.MAIL_PROTOCOL,
                risk=TechniqueRisk.CRITICAL,
                description="Intercepts or modifies SMTP EHLO response to remove 250-STARTTLS capability advertisement.",
                prerequisites=["smtp_proxy_tap"],
                expected_telemetry=["smtp_ehlo_event", "starttls_missing_alert"],
                expected_detections=["STARTTLS-STRIP-001"],
                expected_response="ENFORCE_MTA_STS",
                safe_execution_method="simulated_smtp_ehlo_tamper",
                mitigation_controls=["mta_sts_mode_enforce"],
                tags=["smtp", "starttls", "mitm"],
            ),
            Technique(
                technique_id="TECH-CRED-001",
                name="Plaintext SMTP Auth Over Unencrypted Stream",
                category=TechniqueCategory.CREDENTIALS,
                risk=TechniqueRisk.CRITICAL,
                description="Sends simulated SMTP AUTH PLAIN/LOGIN commands over unencrypted connection following stripped TLS.",
                prerequisites=["smtp_port_open"],
                expected_telemetry=["smtp_auth_event", "unencrypted_auth_warning"],
                expected_detections=["AUTH-PLAINTEXT-001"],
                expected_response="REVOKE_CREDENTIALS",
                safe_execution_method="dummy_token_auth_replay",
                mitigation_controls=["disable_plaintext_auth"],
                tags=["credentials", "smtp", "auth"],
            ),
            Technique(
                technique_id="TECH-CRYPTO-PQC-001",
                name="Post-Quantum Key Exchange Downgrade",
                category=TechniqueCategory.CRYPTOGRAPHY,
                risk=TechniqueRisk.HIGH,
                description="Forces ML-KEM/Kyber post-quantum hybrid TLS 1.3 handshake down to classical ECDH.",
                prerequisites=["pqc_telemetry_sensor"],
                expected_telemetry=["tls_kex_event", "pqc_hybrid_metric"],
                expected_detections=["PQC-DOWNGRADE-001"],
                expected_response="ALERT_CRYPTO_TEAM",
                safe_execution_method="synthetic_kex_key_share_omission",
                mitigation_controls=["pqc_mandatory_policy"],
                tags=["pqc", "quantum", "crypto"],
            ),
            Technique(
                technique_id="TECH-LATERAL-001",
                name="MTA East-West Anomalous Communication",
                category=TechniqueCategory.LATERAL_MOVEMENT,
                risk=TechniqueRisk.HIGH,
                description="Simulates internal mail routing anomaly where an internal relay connects directly to restricted auth server.",
                prerequisites=["network_flow_sensor"],
                expected_telemetry=["flow_event", "unauthorized_peer_alert"],
                expected_detections=["LATERAL-MTA-001"],
                expected_response="BLOCK_IP",
                safe_execution_method="controlled_loopback_probe",
                mitigation_controls=["network_segmentation"],
                tags=["lateral", "network", "east_west"],
            ),
        ]
        for t in builtins:
            self._techniques[t.technique_id] = t

    def get(self, technique_id: str) -> Optional[Technique]:
        return self._techniques.get(technique_id)

    def list_all(self) -> List[Technique]:
        return list(self._techniques.values())

    def filter_by_category(self, category: TechniqueCategory) -> List[Technique]:
        return [t for t in self._techniques.values() if t.category == category]

    def register(self, technique: Technique) -> None:
        self._techniques[technique.technique_id] = technique
