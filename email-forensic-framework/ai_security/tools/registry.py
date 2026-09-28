"""AI Tool Inventory and Capability Registry.
Components 30.24 & 30.34: Registers privileged capabilities (database_query, http_post, file_read, shell_exec).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class ToolType(str, Enum):
    DATABASE_QUERY = "DATABASE_QUERY"
    HTTP_CLIENT = "HTTP_CLIENT"
    FILE_SYSTEM = "FILE_SYSTEM"
    SHELL_EXECUTION = "SHELL_EXECUTION"
    VECTOR_SEARCH = "VECTOR_SEARCH"
    API_INTEGRATION = "API_INTEGRATION"


class ToolRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AIToolRecord:
    tool_id: str
    name: str
    tool_type: ToolType
    risk_level: ToolRiskLevel
    description: str
    requires_approval: bool = False
    is_network_enabled: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "tool_type": self.tool_type.value,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "requires_approval": self.requires_approval,
            "is_network_enabled": self.is_network_enabled,
            "created_at": self.created_at,
        }


class AIToolRegistry:
    """Enterprise registry cataloging privileged capabilities accessible to AI models and agents."""

    def __init__(self):
        self._tools: Dict[str, AIToolRecord] = {}
        self._seed_default_tools()

    def _seed_default_tools(self):
        self.register_tool(
            AIToolRecord(
                tool_id="database_query",
                name="PostgreSQL/Aurora Query Tool",
                tool_type=ToolType.DATABASE_QUERY,
                risk_level=ToolRiskLevel.HIGH,
                description="Executes read/write SQL queries against configured databases.",
            )
        )
        self.register_tool(
            AIToolRecord(
                tool_id="http_post",
                name="HTTP REST Client",
                tool_type=ToolType.HTTP_CLIENT,
                risk_level=ToolRiskLevel.HIGH,
                description="Sends outbound HTTP/REST payloads to external or internal URLs.",
                is_network_enabled=True,
            )
        )
        self.register_tool(
            AIToolRecord(
                tool_id="search_kb",
                name="Vector Knowledge Base Search",
                tool_type=ToolType.VECTOR_SEARCH,
                risk_level=ToolRiskLevel.LOW,
                description="Semantic vector similarity lookup against enterprise knowledge bases.",
            )
        )
        self.register_tool(
            AIToolRecord(
                tool_id="shell_exec",
                name="Bash/PowerShell Execution",
                tool_type=ToolType.SHELL_EXECUTION,
                risk_level=ToolRiskLevel.CRITICAL,
                description="Executes local OS shell commands.",
                requires_approval=True,
            )
        )

    def register_tool(self, tool: AIToolRecord) -> None:
        self._tools[tool.tool_id] = tool

    def get_tool(self, tool_id: str) -> Optional[AIToolRecord]:
        return self._tools.get(tool_id)

    def list_tools(self) -> List[AIToolRecord]:
        return list(self._tools.values())
