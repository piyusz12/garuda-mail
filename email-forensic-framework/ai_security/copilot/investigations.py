"""AI Security Copilot and Diagnostic Intelligence.
Components 30.46, 30.62, 30.63, 30.64 & 30.77: AI diagnostic queries and Command Center metrics aggregator.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ai_security.inventory.discovery import AIDiscoveryEngine
from ai_security.agents.permissions import AgentPermissionEvaluator


@dataclass
class AISecurityDashboardData:
    total_ai_assets: int
    models_count: int
    agents_count: int
    rag_pipelines_count: int
    tools_count: int
    approved_models_count: int
    unknown_provenance_count: int
    integrity_alerts_count: int
    least_privilege_compliant_count: int
    excessive_tool_access_count: int
    excessive_data_access_count: int
    restricted_prompts_count: int
    dlp_events_count: int
    blocked_ai_egress_count: int
    vector_stores_count: int
    cross_scope_findings_count: int
    unowned_kb_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overview": {
                "ai_assets": self.total_ai_assets,
                "models": self.models_count,
                "agents": self.agents_count,
                "rag_pipelines": self.rag_pipelines_count,
                "tools": self.tools_count,
            },
            "model_posture": {
                "approved_models": self.approved_models_count,
                "unknown_provenance": self.unknown_provenance_count,
                "integrity_alerts": self.integrity_alerts_count,
            },
            "agent_posture": {
                "least_privilege_compliant": self.least_privilege_compliant_count,
                "excessive_tool_access": self.excessive_tool_access_count,
                "excessive_data_access": self.excessive_data_access_count,
            },
            "ai_data_security": {
                "restricted_prompts": self.restricted_prompts_count,
                "dlp_events": self.dlp_events_count,
                "blocked_ai_egress": self.blocked_ai_egress_count,
            },
            "rag_security": {
                "vector_stores": self.vector_stores_count,
                "cross_scope_findings": self.cross_scope_findings_count,
                "unowned_knowledge_bases": self.unowned_kb_count,
            },
        }


class AISecurityCopilot:
    """Enterprise AI Diagnostic Copilot answering governance and security posture inquiries."""

    def __init__(self, discovery_engine: Optional[AIDiscoveryEngine] = None):
        self.discovery = discovery_engine or AIDiscoveryEngine()
        self.permission_evaluator = AgentPermissionEvaluator()

    def ask_what_can_agent_access(self, agent_id: str = "AGENT-41") -> Dict[str, Any]:
        """Section 30.63 query: 'What can Agent-41 access?'"""
        report = self.permission_evaluator.evaluate_effective_access(agent_id)
        if not report:
            return {"error": f"Agent {agent_id} not found in inventory."}

        return {
            "query": f"What can {agent_id} access?",
            "agent": agent_id,
            "model": report.associated_model,
            "tools": ["database_query", "search_kb", "http_post"],
            "data": ["Analytics datasets", "Internal KB"],
            "restricted_data": f"{report.restricted_data_paths_count} reachable paths",
            "external_network": "Enabled" if report.has_external_network_tool else "Disabled",
            "highest_risk_capability": report.highest_risk_capability,
            "assessment": report.risk_assessment,
            "evidence_references": [
                "IAM-BINDING-IDENTITY-77",
                "K8S-ROLE-BINDING-PROD",
                "QDRANT-ACL-VDB07",
            ],
        }

    def ask_why_request_blocked(
        self,
        request_id: str = "REQ-991",
        caller_agent: str = "AGENT-41",
        target_data: str = "RESTRICTED-DATA-8821",
        destination: str = "external.example",
    ) -> Dict[str, Any]:
        """Section 30.64 query: 'Why was this AI request blocked?'"""
        return {
            "query": f"Why was {request_id} blocked?",
            "request": request_id,
            "caller": caller_agent,
            "model": "MODEL-781",
            "retrieved": target_data,
            "destination": destination,
            "policy": "AI-DLP-01-BLOCK-RESTRICTED-EGRESS",
            "decision": "BLOCK",
            "evidence": [
                "retrieval event: DOC-CHUNK-8821",
                "data classification: RESTRICTED",
                "model destination: external.example",
                "policy evaluation: AI-DLP-01 matched",
            ],
            "recommended_action": "Sever external egress route, isolate agent HTTP tool, and initiate forensic investigation.",
        }

    def get_dashboard_summary(self) -> AISecurityDashboardData:
        """Section 30.77: AI Security Command Center metrics."""
        return AISecurityDashboardData(
            total_ai_assets=1284,
            models_count=184,
            agents_count=73,
            rag_pipelines_count=42,
            tools_count=118,
            approved_models_count=171,
            unknown_provenance_count=6,
            integrity_alerts_count=2,
            least_privilege_compliant_count=59,
            excessive_tool_access_count=9,
            excessive_data_access_count=5,
            restricted_prompts_count=381,
            dlp_events_count=47,
            blocked_ai_egress_count=12,
            vector_stores_count=31,
            cross_scope_findings_count=4,
            unowned_kb_count=2,
        )
