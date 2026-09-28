"""Garuda Enterprise AI Security - Threat Hunting Engine.
Phase 30 Section 30.82: Extends Phase 23 threat hunting across AI agents,
models, RAG pipelines, data access, and tool invocation telemetry.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid

from ai_security.events import AISecurityEvent, AIEventType


@dataclass
class AIHuntFinding:
    finding_id: str
    hunt_id: str
    severity: str
    title: str
    description: str
    agent_id: Optional[str]
    model_id: Optional[str]
    evidence: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    remediation_recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "hunt_id": self.hunt_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "remediation_recommendation": self.remediation_recommendation,
        }


@dataclass
class AIHuntQuery:
    hunt_id: str
    title: str
    description: str
    hypothesis: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    def execute(self, events: List[AISecurityEvent], context: Optional[Dict[str, Any]] = None) -> List[AIHuntFinding]:
        raise NotImplementedError("Subclasses must implement execute()")


class SensitiveAccessExternalToolHunt(AIHuntQuery):
    """AI-HUNT-001: Find agents that accessed sensitive/restricted data and
    used external network tools within the time correlation window."""

    def __init__(self, time_window_seconds: float = 300.0):
        super().__init__(
            hunt_id="AI-HUNT-001",
            title="Sensitive Data Retrieval Followed by External Network Tool",
            description="Identifies agents that retrieved RESTRICTED or CONFIDENTIAL data and subsequently invoked an outbound network or HTTP tool within a specified correlation window.",
            hypothesis="An attacker or rogue agent may be exfiltrating sensitive data retrieved via RAG or databases using external network tools.",
            parameters={"time_window_seconds": time_window_seconds},
        )

    def execute(self, events: List[AISecurityEvent], context: Optional[Dict[str, Any]] = None) -> List[AIHuntFinding]:
        findings = []
        window = float(self.parameters.get("time_window_seconds", 300.0))

        # Index events by agent
        agent_sensitive_retrievals: Dict[str, List[AISecurityEvent]] = {}
        for ev in events:
            if not ev.agent_id:
                continue
            is_retrieval = ev.event_type in (AIEventType.AI_RETRIEVAL_EVENT, AIEventType.AI_DLP_EVALUATION)
            classification = ev.payload.get("classification", "").upper()
            if is_retrieval and classification in ("RESTRICTED", "CONFIDENTIAL", "CRITICAL"):
                if ev.agent_id not in agent_sensitive_retrievals:
                    agent_sensitive_retrievals[ev.agent_id] = []
                agent_sensitive_retrievals[ev.agent_id].append(ev)

        # Look for subsequent external tool invocations
        for ev in events:
            if not ev.agent_id or ev.agent_id not in agent_sensitive_retrievals:
                continue
            if ev.event_type == AIEventType.AI_TOOL_INVOKED:
                tool_type = ev.payload.get("tool_type", "").upper()
                tool_name = ev.payload.get("tool_name", "").lower()
                is_external = ev.payload.get("is_external", False) or "http" in tool_name or "curl" in tool_name or tool_type == "NETWORK"
                if is_external:
                    for prev_retrieval in agent_sensitive_retrievals[ev.agent_id]:
                        time_delta = ev.timestamp - prev_retrieval.timestamp
                        if 0 <= time_delta <= window:
                            findings.append(
                                AIHuntFinding(
                                    finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                                    hunt_id=self.hunt_id,
                                    severity="CRITICAL",
                                    title=f"Potential AI Exfiltration by {ev.agent_id}",
                                    description=(
                                        f"Agent {ev.agent_id} retrieved sensitive data ({prev_retrieval.payload.get('classification')}) "
                                        f"and invoked external tool '{tool_name}' within {time_delta:.1f}s."
                                    ),
                                    agent_id=ev.agent_id,
                                    model_id=ev.model_id,
                                    evidence={
                                        "retrieval_event_id": prev_retrieval.event_id,
                                        "retrieval_time": prev_retrieval.timestamp,
                                        "classification": prev_retrieval.payload.get("classification"),
                                        "tool_event_id": ev.event_id,
                                        "tool_name": tool_name,
                                        "tool_time": ev.timestamp,
                                        "time_delta_seconds": time_delta,
                                        "destination": ev.payload.get("destination", "unknown"),
                                    },
                                    remediation_recommendation="Immediately invoke PB-AI-01-TOOL-REVOCATION to revoke network capabilities for this agent and isolate egress.",
                                )
                            )
        return findings


class ModelArtifactHashTamperHunt(AIHuntQuery):
    """AI-HUNT-002: Find model deployments whose artifact hash differs from
    the baseline approved hash in provenance records."""

    def __init__(self):
        super().__init__(
            hunt_id="AI-HUNT-002",
            title="Runtime Model Artifact Hash Tamper or Modification",
            description="Scans deployed models for cryptographic hash discrepancies between running memory/weights and approved production baselines.",
            hypothesis="Adversaries or malicious supply-chain actors may have replaced model weights with a backdoored checkpoint.",
        )

    def execute(self, events: List[AISecurityEvent], context: Optional[Dict[str, Any]] = None) -> List[AIHuntFinding]:
        findings = []
        for ev in events:
            if ev.event_type in (AIEventType.AI_MODEL_DEPLOYED, AIEventType.AI_MODEL_CHANGED):
                current_hash = ev.payload.get("current_hash") or ev.payload.get("runtime_hash")
                approved_hash = ev.payload.get("approved_hash") or ev.payload.get("expected_hash")
                if current_hash and approved_hash and current_hash != approved_hash:
                    findings.append(
                        AIHuntFinding(
                            finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            hunt_id=self.hunt_id,
                            severity="CRITICAL",
                            title=f"Model Artifact Hash Integrity Mismatch on {ev.model_id}",
                            description=f"Model {ev.model_id} runtime hash {current_hash[:16]}... does not match approved hash {approved_hash[:16]}...",
                            agent_id=ev.agent_id,
                            model_id=ev.model_id,
                            evidence={
                                "model_id": ev.model_id,
                                "approved_hash": approved_hash,
                                "current_hash": current_hash,
                                "event_id": ev.event_id,
                            },
                            remediation_recommendation="Quarantine the model immediately with PB-AI-04-MODEL-ISOLATION and trigger forensic verification.",
                        )
                    )
        return findings


class ToolCallRateAnomalyHunt(AIHuntQuery):
    """AI-HUNT-003: Find agents whose tool-call rate increased significantly
    above the baseline threshold."""

    def __init__(self, spike_multiplier: float = 3.0, min_calls: int = 10):
        super().__init__(
            hunt_id="AI-HUNT-003",
            title="Agent Tool Call Volume Spike / Loop Anomaly",
            description="Identifies agents making abnormally high frequencies of tool invocations compared to their configured baseline rate.",
            hypothesis="An autonomous agent may be stuck in an infinite reflection loop or an attacker is executing automated bulk scraping via agent tools.",
            parameters={"spike_multiplier": spike_multiplier, "min_calls": min_calls},
        )

    def execute(self, events: List[AISecurityEvent], context: Optional[Dict[str, Any]] = None) -> List[AIHuntFinding]:
        findings = []
        spike_multiplier = float(self.parameters.get("spike_multiplier", 3.0))
        min_calls = int(self.parameters.get("min_calls", 10))

        agent_tool_counts: Dict[str, int] = {}
        agent_baselines: Dict[str, float] = {}

        for ev in events:
            if ev.event_type == AIEventType.AI_TOOL_INVOKED and ev.agent_id:
                agent_tool_counts[ev.agent_id] = agent_tool_counts.get(ev.agent_id, 0) + 1
                if "baseline_rate" in ev.payload:
                    agent_baselines[ev.agent_id] = float(ev.payload["baseline_rate"])

        for agent_id, count in agent_tool_counts.items():
            baseline = agent_baselines.get(agent_id, 3.0)
            if count >= min_calls and count >= (baseline * spike_multiplier):
                findings.append(
                    AIHuntFinding(
                        finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                        hunt_id=self.hunt_id,
                        severity="HIGH",
                        title=f"Abnormal Tool Invocation Spike for {agent_id}",
                        description=f"Agent {agent_id} executed {count} tool calls (baseline: {baseline:.1f}, spike multiplier: {count/baseline:.1f}x).",
                        agent_id=agent_id,
                        model_id=None,
                        evidence={
                            "agent_id": agent_id,
                            "observed_tool_calls": count,
                            "baseline_rate": baseline,
                            "ratio": count / baseline if baseline else count,
                        },
                        remediation_recommendation="Inspect agent trace logs for infinite loops and enforce max step budgets.",
                    )
                )
        return findings


class CrossScopeRAGRetrievalHunt(AIHuntQuery):
    """AI-HUNT-004: Find RAG pipelines retrieving data outside user authorization scope."""

    def __init__(self):
        super().__init__(
            hunt_id="AI-HUNT-004",
            title="Cross-Scope / Cross-Tenant Vector Retrieval Violation",
            description="Searches for vector retrieval events where documents returned did not match caller tenant or classification scope.",
            hypothesis="Improper vector search filtering or missing pre-retrieval authorization allowed multi-tenant cross-retrieval.",
        )

    def execute(self, events: List[AISecurityEvent], context: Optional[Dict[str, Any]] = None) -> List[AIHuntFinding]:
        findings = []
        for ev in events:
            if ev.event_type == AIEventType.AI_RETRIEVAL_EVENT:
                caller_tenant = ev.payload.get("caller_tenant")
                doc_tenants = ev.payload.get("doc_tenants", [])
                cross_tenants = [t for t in doc_tenants if t and caller_tenant and t != caller_tenant]
                if cross_tenants or ev.payload.get("cross_scope_detected", False):
                    findings.append(
                        AIHuntFinding(
                            finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            hunt_id=self.hunt_id,
                            severity="HIGH",
                            title=f"Cross-Tenant Data Retrieval in RAG Pipeline",
                            description=f"Caller from tenant '{caller_tenant}' retrieved documents belonging to unauthorized tenants: {cross_tenants}",
                            agent_id=ev.agent_id,
                            model_id=ev.model_id,
                            evidence={
                                "event_id": ev.event_id,
                                "caller_tenant": caller_tenant,
                                "cross_tenants": cross_tenants,
                                "query": ev.payload.get("query", ""),
                            },
                            remediation_recommendation="Enforce partition-level vector namespace isolation and mandatory pre-retrieval ACL filtering.",
                        )
                    )
        return findings
