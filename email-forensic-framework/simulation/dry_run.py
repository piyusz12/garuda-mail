"""
Phase 24 — Dry Run Engine (Component 39)
Generates non-mutating preview reports for response plans and actions.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from response.actions import ResponseAction
from response.planner import ResponsePlan


@dataclass
class DryRunReport:
    plan_id: str
    target_assets: List[str]
    actions_preview: List[Dict[str, Any]]
    services_affected: List[str]
    change_records_to_create: int
    required_approvals: int
    reversible: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DryRunEngine:
    """Pre-evaluates plans without executing commands or mutating system state."""

    @classmethod
    def execute_dry_run(cls, plan: ResponsePlan) -> DryRunReport:
        previews = []
        services = set()
        req_approvals = 0
        all_reversible = True

        for act in plan.actions:
            previews.append({
                "action_id": act.action_id,
                "name": act.name,
                "target": act.target_asset,
                "would_execute": act.forward_command,
                "would_rollback": act.rollback_command or "NON_REVERSIBLE",
                "risk_class": act.risk_class.value
            })
            if act.target_asset:
                services.add(f"{act.target_asset}:smtp")
            if act.risk_class.value in ["R3", "R4"]:
                req_approvals = max(req_approvals, 2 if act.risk_class.value == "R4" else 1)
            if not act.rollback_command and act.risk_class.value in ["R2", "R3", "R4"]:
                all_reversible = False

        summary = f"Dry run passed for {len(plan.actions)} actions. Would touch {len(services)} services with {req_approvals} approvals required."

        return DryRunReport(
            plan_id=plan.plan_id,
            target_assets=list({a.target_asset for a in plan.actions if a.target_asset}),
            actions_preview=previews,
            services_affected=list(services),
            change_records_to_create=1,
            required_approvals=req_approvals,
            reversible=all_reversible,
            summary=summary
        )
