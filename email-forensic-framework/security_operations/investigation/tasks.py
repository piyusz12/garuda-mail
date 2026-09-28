"""
Phase 25 — Automated Investigation Tasks
Defines reusable modular tasks composed into the Investigation DAG.
"""

from typing import Dict, List, Optional, Any, Callable
import time
from .context import AssetContext, MaintenanceWindowChecker


class InvestigationTask:
    """Base class for an executable task within the Investigation DAG."""

    def __init__(self, name: str, dependencies: Optional[List[str]] = None):
        self.name = name
        self.dependencies = dependencies or []

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class ResolveAssetTask(InvestigationTask):
    """Resolves asset inventory metadata, criticality, and ownership."""

    def __init__(self, asset_registry: Optional[Dict[str, AssetContext]] = None):
        super().__init__(name="ResolveAsset", dependencies=[])
        self.registry = asset_registry or {
            "MTA-07": AssetContext(
                asset_id="MTA-07",
                hostname="mta-07.corp.garudamail.internal",
                ip_address="192.168.10.47",
                criticality="HIGH",
                services=["smtp", "submission", "mta-core"],
                dependencies=["mail-storage-01", "pki-ca-vault"],
            ),
            "MTA-01": AssetContext(
                asset_id="MTA-01",
                hostname="mta-01.corp.garudamail.internal",
                ip_address="192.168.10.41",
                criticality="CRITICAL",
                services=["smtp", "imap"],
                dependencies=["core-gateway"],
            ),
        }

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = context.get("asset_id", "UNKNOWN-ASSET")
        asset_info = self.registry.get(asset_id)
        if not asset_info:
            asset_info = AssetContext(
                asset_id=asset_id,
                hostname=f"{asset_id.lower()}.local",
                ip_address="10.0.0.1",
                criticality="MEDIUM",
            )
        return {
            "asset_id": asset_info.asset_id,
            "hostname": asset_info.hostname,
            "criticality": asset_info.criticality,
            "services": asset_info.services,
            "dependencies": asset_info.dependencies,
        }


class GetCertificateHistoryTask(InvestigationTask):
    """Retrieves historic X.509 certificate rotations, issuers, and thumbprints."""

    def __init__(self):
        super().__init__(name="GetCertificateHistory", dependencies=["ResolveAsset"])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = context.get("asset_id", "")
        # Mock/simulated or retrieved certificate lineage
        return {
            "certificate_history": [
                {
                    "cert_id": "CERT-2026-PRIMARY",
                    "fingerprint": "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0",
                    "issuer": "Garuda Enterprise Internal CA",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "is_trusted": True,
                },
                {
                    "cert_id": "CERT-UNKNOWN-UNTRUSTED",
                    "fingerprint": "11223344556677889900aabbccddeeff00112233",
                    "issuer": "Self-Signed Untrusted Authority",
                    "valid_until": "2026-10-01T00:00:00Z",
                    "is_trusted": False,
                },
            ],
            "active_cert_trusted": False if context.get("certificate_id") == "CERT-UNKNOWN-UNTRUSTED" else True,
        }


class GetTLSHistoryTask(InvestigationTask):
    """Retrieves TLS protocol negotiation history and cipher baselines."""

    def __init__(self):
        super().__init__(name="GetTLSHistory", dependencies=["ResolveAsset"])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "tls_history_sessions": 1284,
            "min_tls_version_observed": "TLSv1.0" if context.get("asset_id") == "MTA-07" else "TLSv1.2",
            "active_ciphersuites": ["TLS_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA"],
            "has_legacy_negotiation": context.get("asset_id") == "MTA-07",
        }


class GetJA4HistoryTask(InvestigationTask):
    """Retrieves client/server JA4 and JA4S TLS fingerprint history."""

    def __init__(self):
        super().__init__(name="GetJA4History", dependencies=["ResolveAsset"])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        ja4 = context.get("ja4", "t13d1516h2_8daaf6152771_b0da82dd1654")
        # Check if JA4 is rare or anomalous
        known_ja4s = {"t13d1516h2_8daaf6152771_b0da82dd1654", "t12d0804h2_123456789abc_def012345678"}
        is_rare = ja4 not in known_ja4s
        return {
            "ja4_fingerprint": ja4,
            "is_rare_ja4": is_rare,
            "frequency_last_90d": 1 if is_rare else 42910,
        }


class GetRecentChangesTask(InvestigationTask):
    """Cross-references ITSM change tickets and deployment logs."""

    def __init__(self, maintenance_checker: Optional[MaintenanceWindowChecker] = None):
        super().__init__(name="GetRecentChanges", dependencies=["ResolveAsset"])
        self.checker = maintenance_checker or MaintenanceWindowChecker()

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = context.get("asset_id", "")
        ts = context.get("timestamp", time.time())
        in_maint, window = self.checker.is_in_maintenance(asset_id, ts)

        recent_changes = []
        if in_maint and window:
            recent_changes.append({
                "ticket_id": window.change_ticket_id,
                "status": "APPROVED",
                "window_id": window.window_id,
                "description": window.description,
            })

        return {
            "in_maintenance_window": in_maint,
            "recent_change_tickets": recent_changes,
            "is_expected_change": in_maint and len(recent_changes) > 0,
        }


class GetHistoricalCasesTask(InvestigationTask):
    """Queries Phase 22 Lakehouse for recurrence of similar anomalies."""

    def __init__(self):
        super().__init__(name="GetHistoricalCases", dependencies=["ResolveAsset"])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = context.get("asset_id", "")
        # Simulated recurrence detection
        has_recurrence = asset_id == "MTA-07"
        return {
            "has_historical_recurrence": has_recurrence,
            "recurrence_count_90d": 3 if has_recurrence else 0,
            "linked_case_ids": ["CASE-882", "CASE-441"] if has_recurrence else [],
            "last_recurrence_iso": "2026-04-18T10:14:00Z" if has_recurrence else None,
        }


class GetThreatIntelTask(InvestigationTask):
    """Enriches IP/JA4/Destination indicators against Threat Intelligence."""

    def __init__(self):
        super().__init__(name="GetThreatIntel", dependencies=[])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        dst = context.get("destination") or "192.168.1.1"
        is_malicious = "malicious" in str(dst).lower() or dst == "198.51.100.99"
        return {
            "threat_score": 85 if is_malicious else 10,
            "associated_threat_actors": ["APT-CRYPTO-DOWNGRADE"] if is_malicious else [],
            "reputation": "MALICIOUS" if is_malicious else "BENIGN",
        }


class GetDependenciesTask(InvestigationTask):
    """Determines dependent services and external consumers for blast-radius calculation."""

    def __init__(self):
        super().__init__(name="GetDependencies", dependencies=["ResolveAsset"])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = context.get("asset_id", "")
        return {
            "dependent_services": ["outbound-relays", "inbound-postfix-proxy"] if asset_id == "MTA-07" else [],
            "external_clients": 3 if asset_id == "MTA-07" else 1,
            "critical_dependencies": 1 if asset_id == "MTA-07" else 0,
            "blast_radius_ratio": 0.28 if asset_id == "MTA-07" else 0.05,
        }
