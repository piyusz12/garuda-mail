"""
Deterministic-security-context features (Phase 5, Section 31, 33).

IMPORTANT (Section 32): this module converts Phase 4's *raw rule
findings* into contextual features for the AI layer. It must never read or
derive a final fused risk score - that would create a circular dependency
(risk score -> AI -> risk score) since the risk score doesn't exist until
Phase 7 runs downstream of this.
"""

from typing import Dict


def extract_security_features(session: dict) -> Dict[str, object]:
    findings = session.get("security_findings") or {}
    dns = session.get("dns_findings") or {}

    security_keys = [
        "tls_deprecated", "weak_cipher", "weak_certificate", "certificate_expired",
        "hostname_mismatch", "no_forward_secrecy", "plaintext_auth", "starttls_failure",
    ]
    dns_keys = [
        "mta_sts_present", "mta_sts_enforced", "mta_sts_tls_mismatch",
        "dane_present", "dane_match", "dane_mismatch", "dnssec_validated",
    ]

    features: Dict[str, object] = {
        f"security.{k}": int(bool(findings.get(k, False))) for k in security_keys
    }
    features.update({f"security.{k}": int(bool(dns.get(k, False))) for k in dns_keys})
    return features
