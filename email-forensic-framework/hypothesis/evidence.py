"""
Phase 23 - Evidence Collector.
Retrieves supporting forensic evidence from Lakehouse and Graph for hypothesis validation.
"""
from typing import Dict, List, Any

class EvidenceCollector:
    """Queries lakehouse data to gather positive evidence for an investigation hypothesis."""

    @classmethod
    def collect_for_asset_ja4(cls, lakehouse: Any, asset_id: str, ja4_fingerprint: str) -> List[Dict[str, Any]]:
        evidence = []
        if not lakehouse or not hasattr(lakehouse, "storage"):
            return evidence

        for obj in lakehouse.storage.values():
            if getattr(obj, "is_deleted", False):
                continue
            data = getattr(obj, "data", {})
            if str(data.get("asset", "")).lower() == str(asset_id).lower() and str(data.get("ja4", "")).lower() == str(ja4_fingerprint).lower():
                evidence.append({
                    "evidence_id": obj.object_id,
                    "layer": obj.layer,
                    "timestamp": obj.timestamp.isoformat() if hasattr(obj.timestamp, "isoformat") else str(obj.timestamp),
                    "summary": f"Observed session on {asset_id} with JA4 {ja4_fingerprint} negotiating {data.get('tls_version')}"
                })
        return evidence
