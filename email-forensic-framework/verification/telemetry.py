"""
Phase 24 — Passive Telemetry Verification (Component 23)
Inspects active passive network telemetry to confirm that actual wire traffic reflects remediation.
"""

from typing import Dict, Any, List, Optional
import time


class TelemetryVerifier:
    """Verifies that actual reassembled network sessions conform to security remediation."""

    @classmethod
    def verify_observed_telemetry(
        cls,
        asset_id: str,
        prohibited_protocols: Optional[List[str]] = None,
        observed_sessions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        prohibited = prohibited_protocols or ["TLS 1.0", "TLS 1.1", "PLAINTEXT"]
        
        # If simulated or real sessions passed
        sessions = observed_sessions or []
        violating_sessions = []

        for s in sessions:
            proto = s.get("tls_version", "PLAINTEXT")
            if proto in prohibited and (s.get("asset") == asset_id or s.get("serverIp") == asset_id):
                violating_sessions.append(s)

        passed = len(violating_sessions) == 0

        return {
            "asset_id": asset_id,
            "layer": "NETWORK_TELEMETRY",
            "passed": passed,
            "total_observed_sessions": len(sessions),
            "prohibited_protocols": prohibited,
            "violating_sessions_count": len(violating_sessions),
            "remediation_verified": passed,
            "summary": f"Observed {len(sessions)} sessions on {asset_id}. Prohibited traffic count: {len(violating_sessions)}."
        }
