"""
Phase 24 — Incident Triage Engine
Enriches incidents with criticality, recurrence, blast radius scope, and cryptographic impact.
"""

from typing import Dict, List, Any, Optional
from incident.models import Incident, IncidentSeverity


class IncidentTriageEngine:
    """Enriches incidents with enterprise asset topology and historical forensic intelligence."""

    def __init__(self, asset_metadata: Optional[Dict[str, Dict[str, Any]]] = None, historical_recurrence_db: Optional[Dict[str, int]] = None):
        # Default enterprise asset criticality directory
        self.asset_metadata = asset_metadata or {
            "MTA-01": {"criticality": "HIGH", "business_importance": "Core Outbound Relay", "services": ["smtp-out", "postfix"]},
            "MTA-02": {"criticality": "HIGH", "business_importance": "Core Inbound MX", "services": ["smtp-in", "exim"]},
            "MTA-03": {"criticality": "MEDIUM", "business_importance": "Internal Submission", "services": ["submission", "dovecot"]},
            "MTA-04": {"criticality": "CRITICAL", "business_importance": "Executive Secure Mail Hub", "services": ["smtp-tls", "postfix"]},
            "MTA-07": {"criticality": "CRITICAL", "business_importance": "Cross-Border Partner Gateway", "services": ["smtp-relay", "postfix"]},
            "MTA-08": {"criticality": "MEDIUM", "business_importance": "Marketing Automation Relay", "services": ["smtp-bulk"]},
            "MTA-11": {"criticality": "LOW", "business_importance": "Dev / Staging Relay", "services": ["smtp-dev"]},
        }
        self.historical_recurrence_db = historical_recurrence_db or {
            "DET-TLS-001": 2,
            "DET-TLS-221": 3,
            "DET-CIPHER-002": 1,
            "DET-AUTH-003": 4,
            "STARTTLS_STRIP": 2,
        }

    def triage_incident(self, incident: Incident) -> Dict[str, Any]:
        """Performs automated enrichment and populates incident.triage_data."""
        # 1. Asset criticality & business importance
        asset_criticalities = []
        services = set()
        for a in incident.affected_assets:
            meta = self.asset_metadata.get(a, {"criticality": "MEDIUM", "business_importance": "General Relay", "services": []})
            asset_criticalities.append(meta["criticality"])
            for s in meta.get("services", []):
                services.add(s)

        has_critical_asset = "CRITICAL" in asset_criticalities
        has_high_asset = "HIGH" in asset_criticalities
        overall_asset_criticality = "CRITICAL" if has_critical_asset else ("HIGH" if has_high_asset else "MEDIUM")

        # 2. Historical recurrence
        recurrence_count = 0
        for d in incident.detections:
            recurrence_count += self.historical_recurrence_db.get(d, 0)
        has_recurrence = recurrence_count > 0

        # 3. Scope calculation
        total_enterprise_assets = max(len(self.asset_metadata), 1)
        scope_ratio = min(1.0, len(incident.affected_assets) / total_enterprise_assets)

        # 4. Cryptographic & Certificate Impact
        is_crypto_issue = any("TLS" in d or "CIPHER" in d or "CERT" in d for d in incident.detections) or "CRYPTO" in incident.title.upper()
        crypto_impact = "HIGH" if is_crypto_issue and (has_critical_asset or len(incident.affected_assets) > 2) else ("MEDIUM" if is_crypto_issue else "LOW")

        # 5. Current exposure
        current_exposure = "ACTIVE_TRAFFIC" if incident.status.value in ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT"] else "CONTAINED"

        triage_report = {
            "asset_criticality": overall_asset_criticality,
            "critical_assets_count": asset_criticalities.count("CRITICAL"),
            "high_assets_count": asset_criticalities.count("HIGH"),
            "affected_services": list(services),
            "historical_recurrence": has_recurrence,
            "recurrence_count": recurrence_count,
            "scope_ratio": round(scope_ratio, 2),
            "scope_description": f"{len(incident.affected_assets)} / {total_enterprise_assets} enterprise assets affected",
            "cryptographic_impact": crypto_impact,
            "certificate_impact": "UNEXPIRED_OR_REPLACED" if not any("CERT" in d for d in incident.detections) else "REVOCATION_OR_MISMATCH_EXPOSURE",
            "current_exposure": current_exposure,
            "confidence": 0.94 if has_recurrence else 0.88,
        }

        incident.triage_data = triage_report
        incident.add_timeline_event(
            event_type="INCIDENT_TRIAGED",
            description=f"Incident enriched: Criticality={overall_asset_criticality}, Recurrence={has_recurrence}, Scope={scope_ratio*100:.0f}%",
            actor="triage_engine",
            details=triage_report
        )
        return triage_report
