"""
Phase 23 - Counter-Evidence Engine.
Actively seeks disconfirming evidence to prevent confirmation bias in autonomous investigations.
"""
from typing import Dict, List, Any, Tuple

class CounterEvidenceEngine:
    """Evaluates whether an observed anomaly is actually an approved deployment, vendor update, or ubiquitous pattern."""

    @classmethod
    def evaluate_counter_evidence(
        cls,
        lakehouse: Any,
        asset_id: str,
        ja4_fingerprint: str,
        approved_deployments: List[Dict[str, Any]] = None,
        known_vendor_fingerprints: List[str] = None
    ) -> Tuple[List[str], float]:
        """
        Returns (counter_evidence_statements, counter_evidence_factor [0.0 - 1.0]).
        """
        counter_statements = []
        weight = 0.0
        approved_deployments = approved_deployments or []
        known_vendor_fingerprints = known_vendor_fingerprints or ["JA4-MTA-STABLE", "JA4-POSTFIX-OFFICIAL"]

        # Check 1: Is JA4 a known benign vendor fingerprint?
        if ja4_fingerprint in known_vendor_fingerprints:
            counter_statements.append(f"JA4 '{ja4_fingerprint}' is cataloged in known benign vendor library.")
            weight += 0.50

        # Check 2: Was there an approved deployment window on this asset?
        for dep in approved_deployments:
            if dep.get("asset") == asset_id and dep.get("status") == "APPROVED":
                counter_statements.append(f"Approved change request '{dep.get('change_id')}' logged for asset {asset_id}.")
                weight += 0.40
                break

        # Check 3: Is this JA4 ubiquitous across many peer assets?
        if lakehouse and hasattr(lakehouse, "storage"):
            assets_with_ja4 = set()
            for obj in lakehouse.storage.values():
                if getattr(obj, "is_deleted", False):
                    continue
                d = getattr(obj, "data", {})
                if str(d.get("ja4", "")).lower() == str(ja4_fingerprint).lower():
                    assets_with_ja4.add(d.get("asset"))
            
            if len(assets_with_ja4) >= 5:
                counter_statements.append(f"JA4 '{ja4_fingerprint}' is broadly deployed across {len(assets_with_ja4)} assets, suggesting standard enterprise distribution.")
                weight += 0.35

        factor = min(1.0, round(weight, 3))
        return counter_statements, factor
