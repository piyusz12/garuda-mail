"""AI Agent Behavior Analytics and Anomaly Detection.
Components 30.27 & 30.80: Establishes normal operational baselines and flags anomalous tool call rates and data access spikes.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class AgentAnomalyType(str, Enum):
    AI_BEHAVIOR_ANOMALY = "AI_BEHAVIOR_ANOMALY"
    TOOL_LOOP_ANOMALY = "TOOL_LOOP_ANOMALY"
    UNAUTHORIZED_DATA_ACCESS = "UNAUTHORIZED_DATA_ACCESS"
    UNEXPECTED_EGRESS = "UNEXPECTED_EGRESS"


@dataclass
class AgentBehaviorAnomalyFinding:
    finding_id: str
    agent_id: str
    anomaly_type: AgentAnomalyType
    severity: str  # "HIGH", "CRITICAL", "MEDIUM"
    title: str
    description: str
    observed_metric: Dict[str, Any]
    baseline_metric: Dict[str, Any]
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "observed_metric": self.observed_metric,
            "baseline_metric": self.baseline_metric,
            "detected_at": self.detected_at,
        }


class AgentBehaviorAnalytics:
    """Detects behavioral drift and tool execution anomalies compared to historical baselines."""

    def __init__(self):
        # agent_id -> { "db_queries_per_req": int, "http_calls_per_req": int }
        self._baselines: Dict[str, Dict[str, int]] = {
            "AGENT-41": {"db_queries": 2, "http_calls": 0, "max_iterations": 10},
            "AGENT-DEV-BOT": {"db_queries": 0, "http_calls": 0, "max_iterations": 5},
        }

    def evaluate_agent_activity(
        self,
        agent_id: str,
        observed_db_queries: int,
        observed_http_calls: int,
        observed_iterations: int = 1,
    ) -> List[AgentBehaviorAnomalyFinding]:
        findings: List[AgentBehaviorAnomalyFinding] = []
        baseline = self._baselines.get(agent_id, {"db_queries": 5, "http_calls": 0, "max_iterations": 10})

        # 1. Behavior Anomaly (DB / HTTP surge)
        if observed_db_queries > (baseline["db_queries"] * 3) or (baseline["http_calls"] == 0 and observed_http_calls > 0):
            findings.append(
                AgentBehaviorAnomalyFinding(
                    finding_id=f"ABANOM-{agent_id}-{int(time.time()*1000)}",
                    agent_id=agent_id,
                    anomaly_type=AgentAnomalyType.AI_BEHAVIOR_ANOMALY,
                    severity="HIGH",
                    title="Agent Behavioral Anomaly Detected",
                    description=(
                        f"Agent {agent_id} deviated significantly from historical baseline: "
                        f"Observed {observed_db_queries} DB queries (baseline: {baseline['db_queries']}) and "
                        f"{observed_http_calls} external HTTP calls (baseline: {baseline['http_calls']})."
                    ),
                    observed_metric={"db_queries": observed_db_queries, "http_calls": observed_http_calls},
                    baseline_metric=baseline,
                )
            )

        # 2. Tool loop anomaly
        if observed_iterations > baseline["max_iterations"]:
            findings.append(
                AgentBehaviorAnomalyFinding(
                    finding_id=f"ALOOP-{agent_id}-{int(time.time()*1000)}",
                    agent_id=agent_id,
                    anomaly_type=AgentAnomalyType.TOOL_LOOP_ANOMALY,
                    severity="MEDIUM",
                    title="Agent Tool Loop Anomaly",
                    description=f"Agent {agent_id} exceeded maximum iteration threshold: {observed_iterations} > {baseline['max_iterations']}.",
                    observed_metric={"iterations": observed_iterations},
                    baseline_metric={"max_iterations": baseline["max_iterations"]},
                )
            )

        return findings
