"""
Copilot DLP Flow Reasoning Helper.
Component 29.65: Explains why a specific data movement event triggered DLP blocks or restrictions.
"""
from typing import Dict, List, Optional, Any


class CopilotFlowReasoning:
    """Answers: 'Why did this data transfer trigger DLP?' with contextual policy reasons."""

    def explain_dlp_trigger(
        self,
        event_id: str = "DATA-FLOW-91",
        asset_id: str = "DATA-8821",
        destination: str = "external.example",
        identity_id: str = "SERVICE-91",
        workload_id: str = "WORKLOAD-991",
    ) -> Dict[str, Any]:
        return {
            "query": "Why did this data transfer trigger DLP?",
            "event_id": event_id,
            "source_asset": asset_id,
            "classification": "RESTRICTED",
            "destination": destination,
            "identity": identity_id,
            "workload": workload_id,
            "observed_volume": "900,000 records (High relative to baseline: 10,000/day)",
            "matched_policy": "DLP-01-BLOCK-RESTRICTED-EGRESS",
            "decision": "BLOCK",
            "reasons": [
                "Dataset contains RESTRICTED customer PII and payment tokens",
                f"Destination {destination} is an unapproved external endpoint",
                f"Workload {workload_id} initiated anomalous bulk extraction exceeding baseline by 90x",
            ],
            "evidence": [
                "FLOW-EVENT-91",
                "DLP-DEC-991",
                "AURORA-LOG-8821",
                "NET-FLOW-4444",
            ],
            "recommended_action": "Sever network egress path, isolate WORKLOAD-991, and initiate forensic timeline.",
        }
