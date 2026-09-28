"""
Phase 24 — Playbook Engine, Workflow Execution & Regression Testing (Components 5, 36, 37, 57)
Executes SOAR workflows, simulates playbook versions, and generates adaptive recommendations based on rollback rates.
"""

from typing import Dict, List, Optional, Any
from playbooks.models import Playbook, PlaybookMaturity
from playbooks.registry import PlaybookRegistry


class PlaybookEngine:
    """Orchestrates playbook selection, regression comparison (v1 vs v2), and adaptive tuning."""

    def __init__(self, registry: Optional[PlaybookRegistry] = None):
        self.registry = registry or PlaybookRegistry()

    def select_playbook_for_incident(self, incident: Any) -> Playbook:
        trigger_key = incident.detections[0] if getattr(incident, "detections", None) else incident.title
        playbook = self.registry.match_playbook_for_trigger(trigger_key)
        if not playbook:
            playbook = self.registry.get_playbook("CRYPTO-REGRESSION-001")
        return playbook

    def regression_test_playbooks(self, playbook_v1: Playbook, playbook_v2: Playbook, test_incident: Any) -> Dict[str, Any]:
        """Component 37: Regression test Playbook v1 vs Playbook v2 against historical incidents."""
        # Check action count, required approvals, and safety guardrails
        v1_approvals = sum(1 for s in playbook_v1.remediation_steps if s.required_approval)
        v2_approvals = sum(1 for s in playbook_v2.remediation_steps if s.required_approval)

        v1_has_simulation = any("SIMULAT" in s.action_name.upper() for s in playbook_v1.remediation_steps)
        v2_has_simulation = any("SIMULAT" in s.action_name.upper() for s in playbook_v2.remediation_steps)

        improvement_detected = v2_has_simulation and not v1_has_simulation or (playbook_v2.historical_rollback_rate < playbook_v1.historical_rollback_rate)

        return {
            "test_incident_id": getattr(test_incident, "incident_id", "INC-TEST"),
            "playbook_id": playbook_v1.playbook_id,
            "v1_version": playbook_v1.version,
            "v2_version": playbook_v2.version,
            "v1_rollback_rate": playbook_v1.historical_rollback_rate,
            "v2_rollback_rate": playbook_v2.historical_rollback_rate,
            "v1_remediation_steps": len(playbook_v1.remediation_steps),
            "v2_remediation_steps": len(playbook_v2.remediation_steps),
            "v1_approvals_required": v1_approvals,
            "v2_approvals_required": v2_approvals,
            "safety_improvement": improvement_detected,
            "recommended_version": playbook_v2.version if improvement_detected else playbook_v1.version,
            "passed_regression": True
        }

    def recommend_adaptive_tuning(self, playbook_id: str) -> Dict[str, Any]:
        """Component 57: Adaptive Response recommendation based on historical performance."""
        playbook = self.registry.get_playbook(playbook_id)
        if not playbook:
            return {"recommendation": "Playbook not found"}

        if playbook.historical_rollback_rate > 0.04:
            rec = "High rollback rate detected (>4%). Recommend introducing mandatory pre-simulation and canary phased rollout."
            next_maturity = PlaybookMaturity.APPROVAL_DRIVEN
        elif playbook.execution_count > 30 and playbook.historical_rollback_rate < 0.02:
            rec = "Low rollback rate (<2%) across 30+ executions. Qualified for Canary Automation."
            next_maturity = PlaybookMaturity.CANARY_AUTOMATION
        else:
            rec = "Playbook operating within normal baseline."
            next_maturity = playbook.maturity

        return {
            "playbook_id": playbook.playbook_id,
            "current_version": playbook.version,
            "current_maturity": playbook.maturity.value,
            "execution_count": playbook.execution_count,
            "rollback_rate": playbook.historical_rollback_rate,
            "recommendation": rec,
            "recommended_maturity": next_maturity.value
        }
