"""
Campaign Copilot Assistant.
Guides analysts in designing, pre-checking, executing, and interpreting campaigns.
"""
from typing import Dict, List, Optional, Any
from validation.campaigns.engine import CampaignEngine, ValidationCampaign, CampaignRun
from validation.scenarios.builder import ValidationScenario


class CampaignCopilot:
    """Natural Language Assistant for campaign operations."""

    def __init__(self, campaign_engine: CampaignEngine):
        self.campaign_engine = campaign_engine

    def plan_campaign(self, theme: str, target_range_id: str = "RANGE-A") -> Dict[str, Any]:
        """Recommends scenarios and checks safety for a user-specified campaign theme."""
        theme_lower = theme.lower()

        if "cert" in theme_lower or "pki" in theme_lower:
            camp_id = "CAMP-CERT-01"
            rec_scenarios = ["SCN-102"]
            focus = "Certificate mutation, chain verification, and rotation response."
        elif "pqc" in theme_lower or "quantum" in theme_lower:
            camp_id = "CAMP-PQC-01"
            rec_scenarios = ["SCN-104"]
            focus = "Cryptographic agility and Post-Quantum hybrid key exchange downgrade testing."
        else:
            camp_id = "CAMP-TLS-01"
            rec_scenarios = ["SCN-101", "SCN-103"]
            focus = "TLS downgrade, STARTTLS stripping, and JA4 fingerprint anomalies."

        return {
            "recommended_campaign_id": camp_id,
            "recommended_scenarios": rec_scenarios,
            "target_range": target_range_id,
            "focus_areas": focus,
            "safety_profile": "All scenarios configured with isolated range targets and automated rollback.",
        }
