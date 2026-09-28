"""AI Tool Authorization and Least-Privilege Scoping.
Components 30.25 & 30.35: Enforces action-level and table-level least privilege for tool calls.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any


@dataclass
class ToolPermissionContract:
    contract_id: str
    agent_id: str
    tool_id: str
    allowed_actions: List[str]  # e.g. ["SELECT"], ["GET"]
    allowed_resources: List[str]  # e.g. ["analytics.*"], ["internal.vault.garuda"]
    denied_resources: List[str]  # e.g. ["customer_vault.*", "external.*"]


class ToolAuthorizationEngine:
    """Enforces fine-grained permission contracts on tool invocations."""

    def __init__(self):
        # key: f"{agent_id}:{tool_id}"
        self._contracts: Dict[str, ToolPermissionContract] = {}
        self._seed_default_contracts()

    def _seed_default_contracts(self):
        # AGENT-41 database contract: Can only SELECT on analytics tables, cannot access customer_vault
        self.register_contract(
            ToolPermissionContract(
                contract_id="TPC-AGENT41-DB",
                agent_id="AGENT-41",
                tool_id="database_query",
                allowed_actions=["SELECT"],
                allowed_resources=["analytics_reporting", "public_catalog"],
                denied_resources=["customer_vault", "payment_tokens", "DATA-8821"],
            )
        )
        # AGENT-41 HTTP contract: Can only call approved internal endpoints, denied external
        self.register_contract(
            ToolPermissionContract(
                contract_id="TPC-AGENT41-HTTP",
                agent_id="AGENT-41",
                tool_id="http_post",
                allowed_actions=["POST", "GET"],
                allowed_resources=["https://api.internal.garuda"],
                denied_resources=["external.example", "https://unapproved.external.io"],
            )
        )

    def register_contract(self, contract: ToolPermissionContract) -> None:
        key = f"{contract.agent_id}:{contract.tool_id}"
        self._contracts[key] = contract

    def authorize_invocation(
        self,
        agent_id: str,
        tool_id: str,
        action: str,
        target_resource: str,
    ) -> bool:
        key = f"{agent_id}:{tool_id}"
        contract = self._contracts.get(key)
        if not contract:
            return False  # Default deny if no contract exists

        # Action check
        if action.upper() not in [a.upper() for a in contract.allowed_actions]:
            return False

        # Explicit deny check
        for denied in contract.denied_resources:
            if denied in target_resource:
                return False

        # Allowed resource check
        for allowed in contract.allowed_resources:
            if allowed in target_resource or allowed.endswith(".*"):
                return True

        return False
