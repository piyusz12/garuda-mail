"""AI DLP Enforcement and Simulation Engine.
Components 30.13, 30.31, 30.40: Evaluates AI data movement, executes blocking decisions, and simulates policy impact.
"""
from typing import Dict, List, Optional, Any
import uuid
import time

from data_security.inventory.normalization import ClassificationLevel
from ai_security.dlp.decisions import AIDLPAction, AIDLPDecision
from ai_security.dlp.policies import AIDLPPolicy


class AIDLPEnforcementEngine:
    """Enforces DLP policies on prompts, RAG retrieval, agent tool calls, and model completions."""

    def __init__(self, custom_policies: Optional[List[AIDLPPolicy]] = None):
        self._policies: Dict[str, AIDLPPolicy] = {}
        if custom_policies:
            for p in custom_policies:
                self._policies[p.policy_id] = p
        else:
            self._seed_default_policies()
        self._decisions_log: List[AIDLPDecision] = []

    def _seed_default_policies(self):
        # AI-DLP-01: Block external egress of RESTRICTED customer data via AI tools
        self.register_policy(
            AIDLPPolicy(
                policy_id="AI-DLP-01-BLOCK-RESTRICTED-EGRESS",
                name="Block External Egress of Restricted Data from AI Agents",
                target_classifications=[ClassificationLevel.RESTRICTED],
                action=AIDLPAction.BLOCK,
                prohibit_external_model=True,
                prohibit_external_tool=True,
                max_record_threshold=100,
            )
        )
        # AI-DLP-02: Restrict unapproved bulk transfers over 10k records
        self.register_policy(
            AIDLPPolicy(
                policy_id="AI-DLP-02-BULK-RESTRICTION",
                name="Restrict Massive Bulk Transfers via AI",
                target_classifications=[ClassificationLevel.RESTRICTED, ClassificationLevel.CONFIDENTIAL],
                action=AIDLPAction.RESTRICT,
                prohibit_external_model=False,
                prohibit_external_tool=False,
                max_record_threshold=10000,
            )
        )

    def register_policy(self, policy: AIDLPPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[AIDLPPolicy]:
        return self._policies.get(policy_id)

    def list_policies(self) -> List[AIDLPPolicy]:
        return list(self._policies.values())

    def evaluate_ai_event(self, event_dict: Dict[str, Any]) -> AIDLPDecision:
        triggered_reasons: List[str] = []
        matched_policy_id: Optional[str] = None
        final_action = AIDLPAction.ALLOW

        for policy in self._policies.values():
            is_violated, reason = policy.evaluate(event_dict)
            if is_violated:
                triggered_reasons.append(reason)
                matched_policy_id = policy.policy_id
                if policy.action == AIDLPAction.BLOCK:
                    final_action = AIDLPAction.BLOCK
                    break
                elif policy.action == AIDLPAction.RESTRICT and final_action != AIDLPAction.BLOCK:
                    final_action = AIDLPAction.RESTRICT

        decision = AIDLPDecision(
            decision_id=f"AIDEC-{uuid.uuid4().hex[:8].upper()}",
            event_id=event_dict.get("event_id", f"AIEVT-{int(time.time()*1000)}"),
            action=final_action,
            matched_policy_id=matched_policy_id,
            reasons=triggered_reasons if triggered_reasons else ["AI data flow complies with all active DLP policies."],
            source_asset_id=event_dict.get("source_asset_id", "UNKNOWN"),
            caller_agent_id=event_dict.get("agent_id", "UNKNOWN"),
            destination=event_dict.get("destination", "internal"),
            confidence=0.98 if matched_policy_id else 1.0,
            is_blocked=(final_action == AIDLPAction.BLOCK),
        )
        self._decisions_log.append(decision)
        return decision

    def simulate_policy(self, policy: AIDLPPolicy, historical_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Pre-evaluates a proposed AI DLP policy against historical requests without enforcement."""
        blocked_count = 0
        restricted_count = 0
        affected_agents = set()

        for ev in historical_events:
            is_violated, _ = policy.evaluate(ev)
            if is_violated:
                if policy.action == AIDLPAction.BLOCK:
                    blocked_count += 1
                else:
                    restricted_count += 1
                if "agent_id" in ev:
                    affected_agents.add(ev["agent_id"])

        return {
            "simulation_id": f"SIM-AIDLP-{policy.policy_id}",
            "policy_id": policy.policy_id,
            "historical_events_evaluated": len(historical_events),
            "would_block_count": blocked_count,
            "would_restrict_count": restricted_count,
            "affected_agents": sorted(list(affected_agents)),
            "summary": f"Policy would intercept {blocked_count + restricted_count} AI events across {len(affected_agents)} agents.",
        }

    def list_decisions(self) -> List[AIDLPDecision]:
        return list(self._decisions_log)
