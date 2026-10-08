from __future__ import annotations

from typing import Any, Dict, List


class Guardrails:
    """Safety guardrails for the investigation copilot."""

    DESTRUCTIVE_ACTIONS = {
        "block_ip",
        "disable_account",
        "quarantine_server",
        "revoke_certificate",
        "delete_evidence",
        "change_firewall",
    }

    def evaluate_action(
        self,
        action: str,
        target: str,
        tenant_id: str,
        analyst_id: str,
        role: str,
        permissions: List[str] | None = None,
    ) -> Dict[str, Any]:
        permissions = permissions or []
        lowered = action.lower()
        if lowered in self.DESTRUCTIVE_ACTIONS:
            return {
                "allowed": False,
                "requires_approval": True,
                "reason": "Destructive action requires human approval and a policy simulation before execution.",
                "tenant_id": tenant_id,
                "analyst_id": analyst_id,
                "role": role,
                "target": target,
            }
        if not permissions:
            return {
                "allowed": False,
                "requires_approval": False,
                "reason": "No permissions granted for this action.",
                "tenant_id": tenant_id,
                "analyst_id": analyst_id,
                "role": role,
                "target": target,
            }
        return {
            "allowed": True,
            "requires_approval": False,
            "reason": "Action is read-only or policy-safe.",
            "tenant_id": tenant_id,
            "analyst_id": analyst_id,
            "role": role,
            "target": target,
        }


__all__ = ["Guardrails"]
