"""Garuda Enterprise AI Security - Incident Dispatcher.
Phase 30 Section 30.38 & 30.80 Step 7: Coordinates AI incident case generation,
playbook dispatching, and evidence linking into Phase 25.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid

from ai_security.incident.playbooks import (
    BaseAIPlaybook,
    ToolRevocationPlaybook,
    EgressContainmentPlaybook,
    AgentQuarantinePlaybook,
    ModelIsolationPlaybook,
    AIPlaybookExecutionResult,
)
from ai_security.agents.registry import AgentRegistry
from ai_security.models.registry import AIModelRegistry


@dataclass
class AIIncidentCase:
    case_id: str
    title: str
    severity: str
    trigger_rule: str
    agent_id: Optional[str]
    model_id: Optional[str]
    status: str  # "OPEN", "CONTAINED", "RESOLVED"
    evidence: Dict[str, Any]
    playbook_results: List[AIPlaybookExecutionResult] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "severity": self.severity,
            "trigger_rule": self.trigger_rule,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "status": self.status,
            "evidence": self.evidence,
            "playbook_results": [r.to_dict() for r in self.playbook_results],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class AIIncidentDispatcher:
    """Manages AI incident cases and executes precision containment playbooks."""

    def __init__(
        self,
        agent_registry: Optional[AgentRegistry] = None,
        model_registry: Optional[AIModelRegistry] = None,
    ):
        self.agent_registry = agent_registry or AgentRegistry()
        self.model_registry = model_registry or AIModelRegistry()
        self._cases: Dict[str, AIIncidentCase] = {}
        self._playbooks: Dict[str, BaseAIPlaybook] = {
            "PB-AI-01-TOOL-REVOCATION": ToolRevocationPlaybook(self.agent_registry),
            "PB-AI-02-EGRESS-CONTAINMENT": EgressContainmentPlaybook(),
            "PB-AI-03-AGENT-QUARANTINE": AgentQuarantinePlaybook(self.agent_registry),
            "PB-AI-04-MODEL-ISOLATION": ModelIsolationPlaybook(self.model_registry),
        }

    def create_case(
        self,
        title: str,
        severity: str,
        trigger_rule: str,
        agent_id: Optional[str] = None,
        model_id: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        case_id: Optional[str] = None,
    ) -> AIIncidentCase:
        cid = case_id or f"CASE-{uuid.uuid4().hex[:6].upper()}"
        case = AIIncidentCase(
            case_id=cid,
            title=title,
            severity=severity,
            trigger_rule=trigger_rule,
            agent_id=agent_id,
            model_id=model_id,
            status="OPEN",
            evidence=evidence or {},
        )
        self._cases[cid] = case
        return case

    def get_case(self, case_id: str) -> Optional[AIIncidentCase]:
        return self._cases.get(case_id)

    def list_cases(self) -> List[AIIncidentCase]:
        return list(self._cases.values())

    def execute_playbook(
        self,
        playbook_id: str,
        params: Dict[str, Any],
        case_id: Optional[str] = None,
    ) -> AIPlaybookExecutionResult:
        pb = self._playbooks.get(playbook_id)
        if not pb:
            raise KeyError(f"Playbook '{playbook_id}' not found.")

        result = pb.execute(params)

        if case_id and case_id in self._cases:
            case = self._cases[case_id]
            case.playbook_results.append(result)
            case.updated_at = time.time()
            if result.status == "SUCCESS":
                case.status = "CONTAINED"

        return result
