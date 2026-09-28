"""
Adversary Behaviors and Synthetic Artifact Generators.
Safe emission routines for telemetry verification without harmful payloads.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import random


@dataclass
class AdversaryBehavior:
    behavior_id: str
    technique_id: str
    name: str
    timing_profile: str  # immediate, jittered, slow_burn
    params: Dict[str, Any] = field(default_factory=dict)

    def generate_telemetry_artifacts(self, target_asset: str) -> List[Dict[str, Any]]:
        """
        Safely generates telemetry artifact dictionaries matching what
        passive sensors, network probes, and TLS inspectors produce.
        """
        ts = time.time()
        artifacts = []

        if "TLS" in self.technique_id or "042" in self.technique_id or "JA4" in self.technique_id:
            artifacts.append({
                "event_type": "tls_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "src_ip": "10.100.4.15",
                "dst_ip": "10.0.1.7",
                "dst_port": 25,
                "tls_version": self.params.get("tls_version", "TLS 1.0"),
                "cipher_suite": self.params.get("cipher_suite", "TLS_RSA_WITH_AES_128_CBC_SHA"),
                "ja4": self.params.get("ja4", "t10d0100h0_legacy_probe"),
                "sni": "mail.corporate.domain",
            })
            artifacts.append({
                "event_type": "ja4_event",
                "timestamp": ts + 0.05,
                "asset_id": target_asset,
                "ja4": self.params.get("ja4", "t10d0100h0_legacy_probe"),
                "seen_count_90d": 1,
                "rarity_score": 0.01,
            })
        elif "CERT" in self.technique_id:
            artifacts.append({
                "event_type": "certificate_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "certificate_id": self.params.get("cert_id", "CERT-ROGUE-992"),
                "subject": "CN=mail.corporate.domain, O=Unauthorized Entity",
                "issuer": "CN=Untrusted Self-Signed Root CA",
                "validity_start": "2026-01-01T00:00:00Z",
                "validity_end": "2026-02-01T00:00:00Z",
                "chain_valid": False,
                "is_self_signed": True,
            })
            artifacts.append({
                "event_type": "x509_chain_event",
                "timestamp": ts + 0.02,
                "asset_id": target_asset,
                "chain_length": 2,
                "root_trusted": False,
                "validation_error": "UNTRUSTED_ISSUER",
            })
        elif "STARTTLS" in self.technique_id:
            artifacts.append({
                "event_type": "smtp_ehlo_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "client_ehlo": "relay.untrusted.net",
                "capabilities_advertised": ["250-SIZE 35882400", "250-8BITMIME", "250-ENHANCEDSTATUSCODES"],
                "starttls_advertised": False,
                "stripped_in_transit": True,
            })
        elif "CRED" in self.technique_id:
            artifacts.append({
                "event_type": "smtp_auth_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "auth_mechanism": "PLAIN",
                "channel_encrypted": False,
                "simulated_user": "test_service_account",
            })
        elif "PQC" in self.technique_id:
            artifacts.append({
                "event_type": "tls_kex_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "kex_group": "x25519",  # Classical only, missing ML-KEM/Kyber
                "pqc_hybrid_expected": True,
                "pqc_hybrid_negotiated": False,
            })
        else:
            artifacts.append({
                "event_type": "flow_event",
                "timestamp": ts,
                "asset_id": target_asset,
                "src_ip": "10.0.1.7",
                "dst_ip": "10.0.2.99",
                "dst_port": 8443,
                "unauthorized_peer": True,
            })

        return artifacts
