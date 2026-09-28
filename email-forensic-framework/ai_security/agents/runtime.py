"""AI Agent Runtime Execution Monitor.
Components 30.26 & 30.36: Tracks agent execution cycles: AGENT_START -> RETRIEVE -> LLM -> TOOL -> RESULT -> RESPONSE.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AgentExecutionStepType(str, Enum):
    AGENT_START = "AGENT_START"
    RETRIEVAL_QUERY = "RETRIEVAL_QUERY"
    RETRIEVAL_RESULT = "RETRIEVAL_RESULT"
    MODEL_INFERENCE = "MODEL_INFERENCE"
    TOOL_INVOCATION = "TOOL_INVOCATION"
    TOOL_RESULT = "TOOL_RESULT"
    EXTERNAL_API_CALL = "EXTERNAL_API_CALL"
    AGENT_STOP = "AGENT_STOP"


@dataclass
class AgentRuntimeStep:
    step_id: str
    agent_id: str
    step_type: AgentExecutionStepType
    action_name: str
    target_resource: str
    payload_summary: str
    duration_ms: float
    is_blocked: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "agent_id": self.agent_id,
            "step_type": self.step_type.value,
            "action_name": self.action_name,
            "target_resource": self.target_resource,
            "payload_summary": self.payload_summary,
            "duration_ms": self.duration_ms,
            "is_blocked": self.is_blocked,
            "timestamp": self.timestamp,
        }


class AgentRuntimeMonitor:
    """Records real-time telemetry across agent decision iterations."""

    def __init__(self):
        self._history: Dict[str, List[AgentRuntimeStep]] = {}

    def record_step(self, step: AgentRuntimeStep) -> None:
        if step.agent_id not in self._history:
            self._history[step.agent_id] = []
        self._history[step.agent_id].append(step)

    def get_agent_history(self, agent_id: str) -> List[AgentRuntimeStep]:
        return list(self._history.get(agent_id, []))

    def count_tool_calls_in_session(self, agent_id: str) -> int:
        steps = self._history.get(agent_id, [])
        return sum(1 for s in steps if s.step_type == AgentExecutionStepType.TOOL_INVOCATION)
