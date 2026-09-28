"""
DLP Policy Enforcement Engine and Policy Simulation.
Components 29.31, 29.37 & 29.38: Enforces DLP decisions and simulates policy blast radius against historical flows.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import uuid
import time

from data_security.dlp.decisions import DLPAction, DLPDecisionRecord
from data_security.dlp.policies import DLPPolicy
from data_security.inventory.normalization import ClassificationLevel


class DLPEnforcementEngine:
    """Evaluates data transfers against enterprise DLP policies and executes decisions."""

    def __init__(self, custom_policies: Optional[List[DLPPolicy]] = None):
        self._policies: Dict[str, DLPPolicy] = {}
        if custom_policies:
            for p in custom_policies:
                self._policies[p.policy_id] = p
        else:
            self._seed_default_policies()

    def _seed_default_policies(self):
        # Policy 1: Block external export of RESTRICTED customer data
        p1 = DLPPolicy(
            policy_id="DLP-01-BLOCK-RESTRICTED-EGRESS",
            name="Block External Egress of Restricted Data",
            target_classifications=[ClassificationLevel.RESTRICTED],
            action=DLPAction.BLOCK,
            prohibit_external=True,
            max_record_limit=10000,
        )
        # Policy 2: Restrict unapproved bulk transfers over 250k records
        p2 = DLPPolicy(
            policy_id="DLP-02-BULK-TRANSFER-RESTRICTION",
            name="Restrict Massive Bulk Transfers",
            target_classifications=[ClassificationLevel.RESTRICTED, ClassificationLevel.SENSITIVE],
            action=DLPAction.RESTRICT,
            prohibit_external=False,
            max_record_limit=250000,
        )
        self.register_policy(p1)
        self.register_policy(p2)

    def register_policy(self, policy: DLPPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[DLPPolicy]:
        return self._policies.get(policy_id)

    def list_policies(self) -> List[DLPPolicy]:
        return list(self._policies.values())

    def evaluate_flow(self, flow: Dict[str, Any]) -> DLPDecisionRecord:
        """Evaluates flow against all active policies. If any policy triggers BLOCK, decision is BLOCK."""
        triggered_reasons: List[str] = []
        matched_policy_id: Optional[str] = None
        final_action = DLPAction.ALLOW

        for policy in self._policies.values():
            is_violated, reason = policy.evaluate(flow)
            if is_violated:
                triggered_reasons.append(reason)
                matched_policy_id = policy.policy_id
                if policy.action == DLPAction.BLOCK:
                    final_action = DLPAction.BLOCK
                    break  # Highest precedence
                elif policy.action == DLPAction.RESTRICT and final_action != DLPAction.BLOCK:
                    final_action = DLPAction.RESTRICT

        is_blocked = (final_action == DLPAction.BLOCK)

        return DLPDecisionRecord(
            decision_id=f"DLPDEC-{uuid.uuid4().hex[:8].upper()}",
            event_id=flow.get("event_id", f"EVT-{uuid.uuid4().hex[:6]}"),
            asset_id=flow.get("source_asset_id", "UNKNOWN"),
            action=final_action,
            matched_policy_id=matched_policy_id,
            reasons=triggered_reasons if triggered_reasons else ["Flow complies with all active DLP policies."],
            confidence=0.98 if matched_policy_id else 1.0,
            is_blocked=is_blocked,
        )

    def simulate_policy(self, policy: DLPPolicy, historical_flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Pre-evaluates a proposed DLP policy against historical flow telemetry."""
        blocked_count = 0
        restricted_count = 0
        affected_identities = set()
        affected_workloads = set()

        for flow in historical_flows:
            is_violated, _ = policy.evaluate(flow)
            if is_violated:
                if policy.action == DLPAction.BLOCK:
                    blocked_count += 1
                else:
                    restricted_count += 1
                if "identity_id" in flow:
                    affected_identities.add(flow["identity_id"])
                if "workload_id" in flow:
                    affected_workloads.add(flow["workload_id"])

        return {
            "simulation_id": f"SIM-DLP-{policy.policy_id}",
            "policy_id": policy.policy_id,
            "policy_name": policy.name,
            "historical_flows_evaluated": len(historical_flows),
            "would_block_count": blocked_count,
            "would_restrict_count": restricted_count,
            "affected_identities": sorted(list(affected_identities)),
            "affected_workloads": sorted(list(affected_workloads)),
            "blast_radius_summary": f"Policy would intercept {blocked_count + restricted_count} flows across {len(affected_workloads)} workloads.",
        }
