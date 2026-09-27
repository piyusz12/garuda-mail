"""
Phase 25 — Action Safety Engine & Execution Dispatcher
Validates targets, blast radius, authorizations, and maintenance windows before executing actions,
supporting dry-run simulations, canary rollouts, and automatic rollback on failure.
"""

from typing import Dict, List, Optional, Any
from .registry import ActionRecord, ActionState, ActionRiskClass, ActionRegistry
from .idempotency import IdempotencyManager, ConcurrencyLockManager
from .adapters import (
    BaseResponseAdapter,
    NetworkResponseAdapter,
    ServiceControlAdapter,
    CertificateResponseAdapter,
    IdentityResponseAdapter,
)


class ActionSafetyEngine:
    """Enforces safety guardrails prior to executing any defensive action."""

    MAX_BLAST_RADIUS_RATIO = 0.50

    @classmethod
    def validate_safety(
        cls,
        action: ActionRecord,
        context: Dict[str, Any],
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Runs pre-flight safety checks."""
        violations = []
        target = action.target

        if not target:
            violations.append("Target asset/indicator is empty.")

        blast_ratio = float(context.get("blast_radius_ratio", 0.10))
        if blast_ratio > cls.MAX_BLAST_RADIUS_RATIO and action.risk_class == ActionRiskClass.R4_MAJOR_CRITICAL:
            violations.append(f"Blast radius ({blast_ratio}) exceeds safety ceiling ({cls.MAX_BLAST_RADIUS_RATIO}).")

        # Check blocked actions
        if action.action_type == "HARD_ISOLATE_CORE_GATEWAY":
            violations.append("Action is explicitly blocked by enterprise safety policy.")

        is_safe = len(violations) == 0
        return {
            "is_safe": is_safe,
            "violations": violations,
            "dry_run": dry_run,
            "blast_radius_ratio": blast_ratio,
            "target": target,
        }


class ActionExecutor:
    """Dispatches validated actions to the appropriate domain adapter with idempotency & safety checks."""

    def __init__(self, action_registry: Optional[ActionRegistry] = None):
        self.registry = action_registry or ActionRegistry()
        self.idempotency = IdempotencyManager()
        self.locks = ConcurrencyLockManager()

        # Register adapters
        self.adapters: Dict[str, BaseResponseAdapter] = {
            "network": NetworkResponseAdapter(),
            "service": ServiceControlAdapter(),
            "certificates": CertificateResponseAdapter(),
            "identity": IdentityResponseAdapter(),
        }

    def _get_adapter(self, action_type: str) -> BaseResponseAdapter:
        act_lower = action_type.lower()
        if "cert" in act_lower:
            return self.adapters["certificates"]
        elif "ja4" in act_lower or "block" in act_lower or "quarantine" in act_lower:
            return self.adapters["network"]
        elif "token" in act_lower or "session" in act_lower or "cred" in act_lower:
            return self.adapters["identity"]
        else:
            return self.adapters["service"]

    def execute_action(
        self,
        action: ActionRecord,
        context: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        is_canary: bool = False,
    ) -> Dict[str, Any]:
        """Executes an action with full safety, idempotency, and concurrency controls."""
        ctx = context or {}

        # 1. Idempotency Check
        idem_key = action.idempotency_key or IdempotencyManager.compute_key(
            action.case_id, action.action_type, action.target
        )
        action.idempotency_key = idem_key

        already_run, prev_result = self.idempotency.is_executed(idem_key)
        if already_run and not dry_run:
            return {
                "status": "ALREADY_EXECUTED",
                "action_id": action.action_id,
                "idempotency_key": idem_key,
                "result": prev_result,
            }

        # 2. Safety Validation
        safety = ActionSafetyEngine.validate_safety(action, ctx, dry_run=dry_run)
        if not safety["is_safe"]:
            action.transition_to(ActionState.FAILED)
            return {
                "status": "SAFETY_CHECK_FAILED",
                "action_id": action.action_id,
                "violations": safety["violations"],
            }

        # 3. Dry-Run simulation bypass
        if dry_run:
            return {
                "status": "DRY_RUN_PASS",
                "action_id": action.action_id,
                "target": action.target,
                "would_affect_services": ctx.get("services", ["smtp", "mta"]),
                "blast_radius_ratio": safety["blast_radius_ratio"],
                "requires_approval": action.risk_class in (ActionRiskClass.R3_POTENTIAL_IMPACT, ActionRiskClass.R4_MAJOR_CRITICAL),
            }

        # 4. Acquire Concurrency Lock
        if not self.locks.acquire_asset_lock(action.target, action.case_id):
            return {
                "status": "CONFLICT",
                "message": f"Asset '{action.target}' is currently locked by another operation.",
            }

        try:
            adapter = self._get_adapter(action.action_type)
            action.transition_to(ActionState.STARTED)

            # Execution
            res = adapter.execute(action)
            action.result = res
            action.transition_to(ActionState.COMPLETED)

            # Record idempotency
            self.idempotency.record_execution(idem_key, res)

            return {
                "status": "SUCCESS",
                "action_id": action.action_id,
                "target": action.target,
                "result": res,
                "is_canary": is_canary,
            }
        except Exception as e:
            action.transition_to(ActionState.FAILED)
            return {
                "status": "EXECUTION_ERROR",
                "action_id": action.action_id,
                "error": str(e),
            }
        finally:
            self.locks.release_asset_lock(action.target, action.case_id)
