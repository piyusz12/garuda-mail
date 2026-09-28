"""AI Tool Risk Analysis and Classification.
Component 30.24 & 30.34: Analyzes blast radius, reversibility, and privilege level of AI tools.
"""
from typing import Dict, Any
from ai_security.tools.registry import ToolType, ToolRiskLevel


class ToolRiskAnalyzer:
    """Evaluates risk score of tools based on potential data access, write capability, and network exposure."""

    RISK_WEIGHTS = {
        ToolType.SHELL_EXECUTION: 95.0,
        ToolType.HTTP_CLIENT: 85.0,
        ToolType.DATABASE_QUERY: 75.0,
        ToolType.FILE_SYSTEM: 70.0,
        ToolType.API_INTEGRATION: 60.0,
        ToolType.VECTOR_SEARCH: 25.0,
    }

    @classmethod
    def evaluate_tool_risk(cls, tool_type: ToolType, is_network_enabled: bool, allows_write: bool) -> Dict[str, Any]:
        base_score = cls.RISK_WEIGHTS.get(tool_type, 50.0)
        if is_network_enabled:
            base_score = min(100.0, base_score + 15.0)
        if allows_write:
            base_score = min(100.0, base_score + 10.0)

        rating = "CRITICAL" if base_score >= 85.0 else ("HIGH" if base_score >= 70.0 else ("MEDIUM" if base_score >= 40.0 else "LOW"))

        return {
            "tool_type": tool_type.value,
            "risk_score": base_score,
            "risk_rating": rating,
            "is_network_enabled": is_network_enabled,
            "allows_write": allows_write,
        }
