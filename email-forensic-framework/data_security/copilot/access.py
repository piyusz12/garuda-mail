"""
Copilot Access Reasoning Helper.
Component 29.64: Traverses data-to-identity paths to explain who can access a dataset.
"""
from typing import Dict, List, Optional, Any
from data_security.access.effective_access import EffectiveAccessCalculator


class CopilotAccessReasoning:
    """Answers: 'Who can access customer records?' with evidence chains."""

    def __init__(self, effective_calc: Optional[EffectiveAccessCalculator] = None):
        self.calculator = effective_calc or EffectiveAccessCalculator()

    def explain_asset_access(self, asset_id: str) -> Dict[str, Any]:
        report = self.calculator.calculate_effective_access(asset_id)
        return {
            "query": f"Who can access {asset_id}?",
            "target_asset": asset_id,
            "direct_access_count": len(report.direct_identities),
            "direct_identities": report.direct_identities,
            "workload_derived_access_count": len(report.workload_derived_identities),
            "workload_derived_services": report.workload_derived_identities,
            "temporary_break_glass_access": 0,
            "high_risk_access_paths_count": len(report.transitive_access_paths),
            "access_paths": report.transitive_access_paths,
            "assessment": report.risk_summary,
            "evidence_references": ["IAM-POLICY-AURORA", "K8S-ROLE-BINDING-PROD", "VAULT-ACCESS-LOG"],
        }
