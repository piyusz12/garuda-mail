"""
Phase 23 - Threat Hunt Templates.
Curated catalog of 10+ battle-tested forensic threat hunts with HQL definitions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class ThreatHuntTemplate:
    template_id: str
    name: str
    description: str
    hql_query: str
    recommended_schedule: str  # Cron or interval (e.g. "daily", "hourly", "0 */6 * * *")
    category: str
    tags: List[str] = field(default_factory=list)


HUNT_TEMPLATES: Dict[str, ThreatHuntTemplate] = {
    "HUNT-TMPL-01": ThreatHuntTemplate(
        template_id="HUNT-TMPL-01",
        name="Legacy TLS Recurrence",
        description="Identifies resurgence of deprecated TLS 1.0 or 1.1 sessions across MTAs following deprecation policies.",
        hql_query="HUNT legacy_tls_recurrence FROM tls_events WHERE tls_version IN ['TLS 1.0', 'TLS 1.1'] WITHIN 90d",
        recommended_schedule="0 0 * * *",  # Daily
        category="PROTOCOL_REGRESSION",
        tags=["tls", "deprecation", "compliance"]
    ),
    "HUNT-TMPL-02": ThreatHuntTemplate(
        template_id="HUNT-TMPL-02",
        name="Unexpected Certificate Rotation",
        description="Detects anomalous certificate fingerprint changes on critical MTA mail servers accompanied by client JA4 rarity shifts.",
        hql_query="HUNT unexpected_certificate_rotation FROM tls_events WHERE certificate.changed = true AND ja4.rarity < 0.05 WITHIN 7d",
        recommended_schedule="0 */6 * * *",  # Every 6 hours
        category="CREDENTIAL_TAMPERING",
        tags=["certificate", "ja4", "rotation"]
    ),
    "HUNT-TMPL-03": ThreatHuntTemplate(
        template_id="HUNT-TMPL-03",
        name="Rare JA4 Outbreak",
        description="Hunts for rare client fingerprints that deviate significantly from baseline across edge mail agents.",
        hql_query="HUNT rare_ja4_outbreak FROM tls_events WHERE ja4_rarity < 0.02 WITHIN 24h",
        recommended_schedule="hourly",
        category="ANOMALY",
        tags=["ja4", "rarity", "fingerprint"]
    ),
    "HUNT-TMPL-04": ThreatHuntTemplate(
        template_id="HUNT-TMPL-04",
        name="New External Destination Relay",
        description="Detects mail sessions establishing outbound TLS connections to never-before-seen ASN destinations.",
        hql_query="HUNT new_external_relay FROM tls_events WHERE destination.is_new = true AND direction = 'OUTBOUND' WITHIN 48h",
        recommended_schedule="0 12 * * *",
        category="EXFILTRATION",
        tags=["relay", "destination", "exfiltration"]
    ),
    "HUNT-TMPL-05": ThreatHuntTemplate(
        template_id="HUNT-TMPL-05",
        name="Crypto Posture Regression",
        description="Hunts for posture degradation where key lengths drop below 2048 bits or non-PQC ciphers are re-enabled.",
        hql_query="HUNT crypto_regression FROM tls_events WHERE key_size < 2048 WITHIN 30d",
        recommended_schedule="weekly",
        category="CRYPTOGRAPHY",
        tags=["crypto", "pqc", "keysize"]
    ),
    "HUNT-TMPL-06": ThreatHuntTemplate(
        template_id="HUNT-TMPL-06",
        name="STARTTLS Downgrade Attack",
        description="Hunts for cleartext SMTP transitions where STARTTLS command was stripped, rejected, or timed out.",
        hql_query="HUNT starttls_downgrade FROM sessions WHERE starttls_stripped = true WITHIN 24h",
        recommended_schedule="hourly",
        category="MITM",
        tags=["smtp", "starttls", "downgrade"]
    ),
    "HUNT-TMPL-07": ThreatHuntTemplate(
        template_id="HUNT-TMPL-07",
        name="Unexpected Cipher Suite Usage",
        description="Identifies TLS handshakes negotiating weak CBC or 3DES cipher suites on internal relays.",
        hql_query="HUNT unexpected_cipher_suite FROM tls_events WHERE cipher_suite IN ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_MD5'] WITHIN 7d",
        recommended_schedule="daily",
        category="CRYPTOGRAPHY",
        tags=["ciphers", "weak-crypto"]
    ),
    "HUNT-TMPL-08": ThreatHuntTemplate(
        template_id="HUNT-TMPL-08",
        name="Certificate Signature Algorithm Downgrade",
        description="Detects certificates signed using obsolete algorithms such as SHA-1 or MD5.",
        hql_query="HUNT cert_algorithm_downgrade FROM certificates WHERE sig_algorithm IN ['SHA1withRSA', 'MD5withRSA'] WITHIN 14d",
        recommended_schedule="weekly",
        category="PKI",
        tags=["x509", "sha1", "pki"]
    ),
    "HUNT-TMPL-09": ThreatHuntTemplate(
        template_id="HUNT-TMPL-09",
        name="Peer-Group Behavioral Deviation",
        description="Compares MTA traffic volume and TLS parameters against sister nodes to catch isolated compromises.",
        hql_query="HUNT peer_deviation FROM tls_events WHERE peer_z_score > 3.0 WITHIN 24h",
        recommended_schedule="hourly",
        category="BEHAVIORAL",
        tags=["peer-group", "behavior", "z-score"]
    ),
    "HUNT-TMPL-10": ThreatHuntTemplate(
        template_id="HUNT-TMPL-10",
        name="Post-Remediation Recurrence Watcher",
        description="Validates whether an issue confirmed remediated has silently recurred within a 90-day grace window.",
        hql_query="HUNT post_remediation_recurrence FROM tls_events WHERE remediation_active = true WITHIN 90d",
        recommended_schedule="daily",
        category="ASSURANCE",
        tags=["remediation", "regression", "watcher"]
    )
}
