"""
Automated Gap Correlation Engine.
Correlates multiple scenario failures to discover common underlying root causes (e.g. shared sensor parser bug).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from .manager import ValidationGap


@dataclass
class CorrelatedRootCause:
    root_cause_id: str
    summary: str
    correlated_gap_ids: List[str]
    affected_techniques: List[str]
    affected_assets: List[str]
    suggested_fix: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_cause_id": self.root_cause_id,
            "summary": self.summary,
            "correlated_gap_ids": self.correlated_gap_ids,
            "affected_techniques": self.affected_techniques,
            "affected_assets": self.affected_assets,
            "suggested_fix": self.suggested_fix,
        }


class GapCorrelationEngine:
    """Groups validation failures across campaigns into singular engineering remediations."""

    @staticmethod
    def correlate(gaps: List[ValidationGap]) -> List[CorrelatedRootCause]:
        # Group by (target_asset, gap_type)
        groups: Dict[tuple, List[ValidationGap]] = {}
        for g in gaps:
            key = (g.target_asset, g.gap_type)
            if key not in groups:
                groups[key] = []
            groups[key].append(g)

        results = []
        idx = 1
        for (asset, g_type), matched_gaps in groups.items():
            if len(matched_gaps) >= 1:
                techs = list(set(g.technique_id for g in matched_gaps))
                if g_type.value == "VISIBILITY_GAP":
                    summary = f"Telemetry ingestion parser deficiency on {asset} affecting {len(techs)} techniques."
                    fix = f"Upgrade and restart network parser/tap on host {asset}."
                elif g_type.value == "DETECTION_GAP":
                    summary = f"Missing or misconfigured detection rules on {asset} for {', '.join(techs)}."
                    fix = f"Deploy or adjust detection rule logic for {', '.join(techs)}."
                elif g_type.value == "RESPONSE_GAP":
                    summary = f"SOAR playbook policy mismatch on {asset} preventing automated or approved response."
                    fix = f"Update playbook policy and approval routing for asset group {asset}."
                else:
                    summary = f"Security control defect on {asset}."
                    fix = "Review security configuration and restore baseline."

                results.append(CorrelatedRootCause(
                    root_cause_id=f"ROOT-CAUSE-{idx:03d}",
                    summary=summary,
                    correlated_gap_ids=[g.gap_id for g in matched_gaps],
                    affected_techniques=techs,
                    affected_assets=[asset],
                    suggested_fix=fix,
                ))
                idx += 1

        return results
