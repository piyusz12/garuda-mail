"""AI Agent Permission Graph and Effective Access Evaluator.
Components 30.23 & 30.33: Resolves effective agent access by combining Model + Tools + Datasets + Network Egress.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time

from ai_security.agents.registry import AgentRegistry, AIAgentRecord


@dataclass
class EffectiveAgentAccessReport:
    agent_id: str
    identity_id: str
    associated_model: str
    authorized_tools: List[str]
    reachable_datasets: List[str]
    restricted_data_paths_count: int
    has_external_network_tool: bool
    highest_risk_capability: str
    risk_assessment: str
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "identity_id": self.identity_id,
            "associated_model": self.associated_model,
            "authorized_tools": self.authorized_tools,
            "reachable_datasets": self.reachable_datasets,
            "restricted_data_paths_count": self.restricted_data_paths_count,
            "has_external_network_tool": self.has_external_network_tool,
            "highest_risk_capability": self.highest_risk_capability,
            "risk_assessment": self.risk_assessment,
            "evaluated_at": self.evaluated_at,
        }


class AgentPermissionEvaluator:
    """Evaluates the composite blast radius and effective permissions of autonomous AI agents."""

    def __init__(self, agent_registry: Optional[AgentRegistry] = None):
        self.agent_registry = agent_registry or AgentRegistry()

    def evaluate_effective_access(self, agent_id: str) -> Optional[EffectiveAgentAccessReport]:
        agent = self.agent_registry.get_agent(agent_id)
        if not agent:
            return None

        has_http = "http_post" in agent.tools or "external_curl" in agent.tools
        has_restricted_data = "DATA-8821" in agent.data_sources
        restricted_paths = 2 if has_restricted_data and has_http else (1 if has_restricted_data else 0)

        highest_risk = "HTTP tool (potential exfiltration vector)" if has_http else ("Database write" if "database_write" in agent.tools else "Read only")

        if has_http and has_restricted_data:
            assessment = "HIGH RISK: Agent can query RESTRICTED customer database and has external HTTP egress capabilities."
        elif has_restricted_data:
            assessment = "CONTROLLED: Agent reads restricted data but lacks external network tools."
        else:
            assessment = "STANDARD: Least-privilege compliant agent."

        return EffectiveAgentAccessReport(
            agent_id=agent.agent_id,
            identity_id=agent.identity_id,
            associated_model=agent.model_id,
            authorized_tools=agent.tools,
            reachable_datasets=agent.data_sources,
            restricted_data_paths_count=restricted_paths,
            has_external_network_tool=has_http,
            highest_risk_capability=highest_risk,
            risk_assessment=assessment,
        )
