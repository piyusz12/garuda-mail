"""AI Tool Invocation Interceptor and Audit.
Component 30.26: Intercepts tool calls at runtime, enforces authorization contracts, and logs executions.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from ai_security.tools.registry import AIToolRegistry
from ai_security.tools.authorization import ToolAuthorizationEngine


@dataclass
class ToolInvocationAudit:
    invocation_id: str
    agent_id: str
    tool_id: str
    action: str
    target_resource: str
    parameters_summary: str
    is_authorized: bool
    status: str  # "EXECUTED", "BLOCKED", "ERROR"
    reason: str
    invoked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "action": self.action,
            "target_resource": self.target_resource,
            "parameters_summary": self.parameters_summary,
            "is_authorized": self.is_authorized,
            "status": self.status,
            "reason": self.reason,
            "invoked_at": self.invoked_at,
        }


class ToolInvocationInterceptor:
    """Evaluates and records tool calls, enforcing blocking on unauthorized resource requests."""

    def __init__(
        self,
        registry: Optional[AIToolRegistry] = None,
        auth_engine: Optional[ToolAuthorizationEngine] = None,
    ):
        self.registry = registry or AIToolRegistry()
        self.auth_engine = auth_engine or ToolAuthorizationEngine()
        self._audits: List[ToolInvocationAudit] = []

    def intercept_call(
        self,
        agent_id: str,
        tool_id: str,
        action: str,
        target_resource: str,
        parameters_summary: str = "",
    ) -> ToolInvocationAudit:
        tool = self.registry.get_tool(tool_id)
        if not tool:
            audit = ToolInvocationAudit(
                invocation_id=f"TINV-{int(time.time()*1000)}",
                agent_id=agent_id,
                tool_id=tool_id,
                action=action,
                target_resource=target_resource,
                parameters_summary=parameters_summary,
                is_authorized=False,
                status="BLOCKED",
                reason=f"Tool {tool_id} is not registered in enterprise capability catalog.",
            )
            self._audits.append(audit)
            return audit

        authorized = self.auth_engine.authorize_invocation(agent_id, tool_id, action, target_resource)
        if not authorized:
            audit = ToolInvocationAudit(
                invocation_id=f"TINV-{int(time.time()*1000)}",
                agent_id=agent_id,
                tool_id=tool_id,
                action=action,
                target_resource=target_resource,
                parameters_summary=parameters_summary,
                is_authorized=False,
                status="BLOCKED",
                reason=f"DENIED: Agent {agent_id} lacks permission contract to execute {action} on {target_resource} via {tool_id}.",
            )
            self._audits.append(audit)
            return audit

        audit = ToolInvocationAudit(
            invocation_id=f"TINV-{int(time.time()*1000)}",
            agent_id=agent_id,
            tool_id=tool_id,
            action=action,
            target_resource=target_resource,
            parameters_summary=parameters_summary,
            is_authorized=True,
            status="EXECUTED",
            reason=f"AUTHORIZED: Invocation allowed under contract.",
        )
        self._audits.append(audit)
        return audit

    def list_audits(self) -> List[ToolInvocationAudit]:
        return list(self._audits)
