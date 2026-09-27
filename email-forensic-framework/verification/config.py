"""
Phase 24 — Configuration State Verification (Component 23)
Validates that daemon configuration files and in-memory daemon options reflect intended policy.
"""

from typing import Dict, Any, List


class ConfigVerifier:
    """Inspects MTA daemon config state to ensure deprecated protocols or weak ciphers are disabled."""

    @classmethod
    def verify_config_state(cls, asset_id: str, connector_registry: Any) -> Dict[str, Any]:
        endpoint = connector_registry.endpoint
        cfg = endpoint.asset_configs.get(asset_id, {})
        protocols = cfg.get("protocols", [])

        # Check for presence of legacy protocols
        has_tls10 = "TLSv1.0" in protocols
        has_tls11 = "TLSv1.1" in protocols
        has_tls12 = "TLSv1.2" in protocols
        has_tls13 = "TLSv1.3" in protocols

        passed = not has_tls10 and not has_tls11 and (has_tls12 or has_tls13)

        return {
            "asset_id": asset_id,
            "layer": "CONFIGURATION",
            "passed": passed,
            "observed_protocols": protocols,
            "has_legacy_tls": has_tls10 or has_tls11,
            "has_modern_tls": has_tls12 or has_tls13,
            "details": f"MTA {asset_id} configuration enforces: {protocols}"
        }
