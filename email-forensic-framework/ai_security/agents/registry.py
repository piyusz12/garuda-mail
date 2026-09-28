"""AI Agent Inventory and Registry.
Components 30.22 & 30.80: Canonical model for enterprise autonomous agents, system policies, and capability bindings.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time


@dataclass
class AIAgentRecord:
    agent_id: str
    name: str
    owner: str
    model_id: str
    identity_id: str
    tools: List[str]
    data_sources: List[str]
    system_policy: str
    max_tool_iterations: int = 10
    is_active: bool = True
    risk_level: str = "HIGH"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "owner": self.owner,
            "model_id": self.model_id,
            "identity_id": self.identity_id,
            "tools": self.tools,
            "data_sources": self.data_sources,
            "system_policy": self.system_policy,
            "max_tool_iterations": self.max_tool_iterations,
            "is_active": self.is_active,
            "risk_level": self.risk_level,
            "created_at": self.created_at,
        }


class AgentRegistry:
    """Central registry tracking all AI agents deployed in enterprise workloads."""

    def __init__(self):
        self._agents: Dict[str, AIAgentRecord] = {}
        self._seed_default_agents()

    def _seed_default_agents(self):
        # AGENT-41: From Section 30.80 End-to-End Scenario
        self.register_agent(
            AIAgentRecord(
                agent_id="AGENT-41",
                name="customer-assistant-agent",
                owner="customer-platform",
                model_id="MODEL-781",
                identity_id="SERVICE-IDENTITY-77",
                tools=["database_query", "search_kb", "http_post"],
                data_sources=["DATA-8821", "VECTOR-DB-07"],
                system_policy="Assist customer platform inquiries within least-privilege boundary.",
                max_tool_iterations=10,
                is_active=True,
                risk_level="HIGH",
            )
        )
        # AGENT-DEV-BOT: Internal engineering bot
        self.register_agent(
            AIAgentRecord(
                agent_id="AGENT-DEV-BOT",
                name="devops-ticket-triager",
                owner="developer-tools",
                model_id="MODEL-781",
                identity_id="SERVICE-DEV-BOT",
                tools=["search_kb", "jira_read"],
                data_sources=["KB-001"],
                system_policy="Triage engineering bug tickets without write privileges.",
                max_tool_iterations=5,
                is_active=True,
                risk_level="MEDIUM",
            )
        )

    def register_agent(self, agent: AIAgentRecord) -> None:
        self._agents[agent.agent_id] = agent

    def get_agent(self, agent_id: str) -> Optional[AIAgentRecord]:
        return self._agents.get(agent_id)

    def list_agents(self) -> List[AIAgentRecord]:
        return list(self._agents.values())

    def disable_agent(self, agent_id: str) -> bool:
        agent = self.get_agent(agent_id)
        if agent:
            agent.is_active = False
            return True
        return False
