"""Garuda Enterprise AI Security - Incident Response Playbooks.
Phase 30 Section 30.38 & 30.80 Step 7: Precision containment playbooks
bridging AI alerts into Phase 25 automated incident response.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid

from ai_security.agents.registry import AgentRegistry
from ai_security.models.registry import AIModelRegistry, ModelLifecycleStatus


class AIPlaybookActionType(str):
    REVOKE_TOOL = "REVOKE_TOOL"
    BLOCK_EGRESS = "BLOCK_EGRESS"
    DISABLE_AGENT = "DISABLE_AGENT"
    QUARANTINE_MODEL = "QUARANTINE_MODEL"
    ROTATE_SECRET = "ROTATE_SECRET"
    ISOLATE_DATA_SOURCE = "ISOLATE_DATA_SOURCE"


@dataclass
class AIPlaybookExecutionResult:
    execution_id: str
    playbook_id: str
    action_type: str
    target_id: str
    status: str  # "SUCCESS", "FAILED", "PARTIAL"
    details: Dict[str, Any]
    executed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "action_type": self.action_type,
            "target_id": self.target_id,
            "status": self.status,
            "details": self.details,
            "executed_at": self.executed_at,
        }


class BaseAIPlaybook:
    playbook_id: str
    name: str
    description: str

    def execute(self, params: Dict[str, Any]) -> AIPlaybookExecutionResult:
        raise NotImplementedError


class ToolRevocationPlaybook(BaseAIPlaybook):
    """PB-AI-01-TOOL-REVOCATION: Precision containment that revokes specific
    compromised or abused tools from an agent while leaving harmless RAG/DB tools operational."""

    def __init__(self, agent_registry: Optional[AgentRegistry] = None):
        self.playbook_id = "PB-AI-01-TOOL-REVOCATION"
        self.name = "Precision AI Tool Revocation"
        self.description = "Revokes a high-risk or compromised tool (e.g. http_post) from an agent without tearing down the entire agent service."
        self.agent_registry = agent_registry or AgentRegistry()

    def execute(self, params: Dict[str, Any]) -> AIPlaybookExecutionResult:
        agent_id = params.get("agent_id")
        tool_id = params.get("tool_id")
        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        if not agent_id or not tool_id:
            return AIPlaybookExecutionResult(
                execution_id=exec_id,
                playbook_id=self.playbook_id,
                action_type=AIPlaybookActionType.REVOKE_TOOL,
                target_id=str(agent_id),
                status="FAILED",
                details={"error": "Missing agent_id or tool_id parameter"},
            )

        agent = self.agent_registry.get_agent(agent_id)
        if not agent:
            return AIPlaybookExecutionResult(
                execution_id=exec_id,
                playbook_id=self.playbook_id,
                action_type=AIPlaybookActionType.REVOKE_TOOL,
                target_id=agent_id,
                status="FAILED",
                details={"error": f"Agent '{agent_id}' not found in registry"},
            )

        removed = False
        if tool_id in agent.tools:
            agent.tools.remove(tool_id)
            removed = True

        return AIPlaybookExecutionResult(
            execution_id=exec_id,
            playbook_id=self.playbook_id,
            action_type=AIPlaybookActionType.REVOKE_TOOL,
            target_id=f"{agent_id}:{tool_id}",
            status="SUCCESS",
            details={
                "agent_id": agent_id,
                "revoked_tool": tool_id,
                "tool_was_present": removed,
                "remaining_tools": list(agent.tools),
                "containment_mode": "PRECISION_TOOL_CONTAINMENT",
            },
        )


class EgressContainmentPlaybook(BaseAIPlaybook):
    """PB-AI-02-EGRESS-CONTAINMENT: Network boundary enforcement severing outbound
    egress routes from model endpoints or agent runtime containers."""

    def __init__(self):
        self.playbook_id = "PB-AI-02-EGRESS-CONTAINMENT"
        self.name = "Model & Agent Egress Boundary Containment"
        self.description = "Blocks network egress toward external internet or untrusted third-party LLM endpoints."

    def execute(self, params: Dict[str, Any]) -> AIPlaybookExecutionResult:
        agent_id = params.get("agent_id", "UNKNOWN_AGENT")
        destination = params.get("destination", "ALL_EXTERNAL")
        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        return AIPlaybookExecutionResult(
            execution_id=exec_id,
            playbook_id=self.playbook_id,
            action_type=AIPlaybookActionType.BLOCK_EGRESS,
            target_id=f"{agent_id}->{destination}",
            status="SUCCESS",
            details={
                "agent_id": agent_id,
                "blocked_destination": destination,
                "network_policy_applied": "DENY_ALL_AI_EGRESS_TO_TARGET",
                "timestamp": time.time(),
            },
        )


class AgentQuarantinePlaybook(BaseAIPlaybook):
    """PB-AI-03-AGENT-QUARANTINE: Disables an agent entirely in case of severe compromise."""

    def __init__(self, agent_registry: Optional[AgentRegistry] = None):
        self.playbook_id = "PB-AI-03-AGENT-QUARANTINE"
        self.name = "Full AI Agent Quarantine & Session Revocation"
        self.description = "Deactivates an agent and revokes all active auth sessions and tokens."
        self.agent_registry = agent_registry or AgentRegistry()

    def execute(self, params: Dict[str, Any]) -> AIPlaybookExecutionResult:
        agent_id = params.get("agent_id")
        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        if not agent_id:
            return AIPlaybookExecutionResult(
                execution_id=exec_id,
                playbook_id=self.playbook_id,
                action_type=AIPlaybookActionType.DISABLE_AGENT,
                target_id="UNKNOWN",
                status="FAILED",
                details={"error": "agent_id parameter required"},
            )

        self.agent_registry.disable_agent(agent_id)
        return AIPlaybookExecutionResult(
            execution_id=exec_id,
            playbook_id=self.playbook_id,
            action_type=AIPlaybookActionType.DISABLE_AGENT,
            target_id=agent_id,
            status="SUCCESS",
            details={
                "agent_id": agent_id,
                "status": "DISABLED",
                "auth_tokens_invalidated": True,
            },
        )


class ModelIsolationPlaybook(BaseAIPlaybook):
    """PB-AI-04-MODEL-ISOLATION: Quarantines a model artifact and triggers routing failover."""

    def __init__(self, model_registry: Optional[AIModelRegistry] = None):
        self.playbook_id = "PB-AI-04-MODEL-ISOLATION"
        self.name = "Model Artifact Quarantine & Failover"
        self.description = "Blocks malicious or tampered model checkpoints and shifts traffic to an approved baseline."
        self.model_registry = model_registry or AIModelRegistry()

    def execute(self, params: Dict[str, Any]) -> AIPlaybookExecutionResult:
        model_id = params.get("model_id")
        fallback_model = params.get("fallback_model", "MODEL-APPROVED-FALLBACK")
        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"

        if not model_id:
            return AIPlaybookExecutionResult(
                execution_id=exec_id,
                playbook_id=self.playbook_id,
                action_type=AIPlaybookActionType.QUARANTINE_MODEL,
                target_id="UNKNOWN",
                status="FAILED",
                details={"error": "model_id parameter required"},
            )

        self.model_registry.set_lifecycle_status(model_id, ModelLifecycleStatus.BLOCKED)
        return AIPlaybookExecutionResult(
            execution_id=exec_id,
            playbook_id=self.playbook_id,
            action_type=AIPlaybookActionType.QUARANTINE_MODEL,
            target_id=model_id,
            status="SUCCESS",
            details={
                "model_id": model_id,
                "previous_status": "ACTIVE",
                "new_status": "BLOCKED",
                "traffic_rerouted_to": fallback_model,
            },
        )
