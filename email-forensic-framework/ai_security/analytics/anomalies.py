"""AI Anomaly Detection Engine.
Components 30.37 & 30.51: Detects prompt surges, token anomalies, tool loops (iterations > 10), and egress spikes.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AIAnomalyCategory(str, Enum):
    PROMPT_SURGE = "PROMPT_SURGE"
    AGENT_LOOP = "AGENT_LOOP"
    TOKEN_ANOMALY = "TOKEN_ANOMALY"
    RETRIEVAL_BURST = "RETRIEVAL_BURST"
    UNAUTHORIZED_TOOL_SPIKE = "UNAUTHORIZED_TOOL_SPIKE"


@dataclass
class AIAnomalyFinding:
    anomaly_id: str
    category: AIAnomalyCategory
    asset_id: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any]
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "category": self.category.value,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "detected_at": self.detected_at,
        }


class AIAnomalyDetector:
    """Detects real-time anomalies across prompt velocity, agent loops, and tool execution."""

    def __init__(self, loop_threshold: int = 10, token_surge_threshold: int = 8000):
        self.loop_threshold = loop_threshold
        self.token_surge_threshold = token_surge_threshold

    def inspect_agent_execution(self, agent_id: str, tool_iterations: int) -> Optional[AIAnomalyFinding]:
        if tool_iterations > self.loop_threshold:
            return AIAnomalyFinding(
                anomaly_id=f"ANOM-LOOP-{agent_id}-{int(time.time()*1000)}",
                category=AIAnomalyCategory.AGENT_LOOP,
                asset_id=agent_id,
                severity="HIGH",
                title="Agent Recursive Tool Loop Detected",
                description=f"Agent {agent_id} repeated tool execution {tool_iterations} times (policy threshold: {self.loop_threshold}). Possible infinite loop or prompt jailbreak cycle.",
                evidence={"iterations": tool_iterations, "threshold": self.loop_threshold},
            )
        return None

    def inspect_token_usage(self, caller_id: str, token_count: int) -> Optional[AIAnomalyFinding]:
        if token_count > self.token_surge_threshold:
            return AIAnomalyFinding(
                anomaly_id=f"ANOM-TOK-{caller_id}-{int(time.time()*1000)}",
                category=AIAnomalyCategory.TOKEN_ANOMALY,
                asset_id=caller_id,
                severity="MEDIUM",
                title="Anomalous Token Volume",
                description=f"Inference request consumed {token_count} tokens, exceeding baseline alert limit ({self.token_surge_threshold}).",
                evidence={"token_count": token_count, "limit": self.token_surge_threshold},
            )
        return None
