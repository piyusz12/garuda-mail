"""Garuda Enterprise AI Security - Detection Engineering Rules.
Phase 30 Section 30.83: Extends Phase 24 detection engineering with
8 core AI-specific security detection rules.
"""
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import time
import uuid

from ai_security.events import AISecurityEvent, AIEventType


@dataclass
class AIDetectionAlert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    description: str
    event_id: str
    agent_id: Optional[str]
    model_id: Optional[str]
    evidence: Dict[str, Any]
    response_playbook: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "evidence": self.evidence,
            "response_playbook": self.response_playbook,
            "timestamp": self.timestamp,
        }


@dataclass
class AIDetectionRule:
    rule_id: str
    name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    target_event: str
    logic: str
    evidence_fields: List[str]
    false_positive_considerations: str
    response_playbook: str
    validation_scenario: str
    enabled: bool = True

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        raise NotImplementedError("Subclasses must implement evaluate()")


class RuleAI001_RestrictedDataExternalModel(AIDetectionRule):
    """AI-001: Restricted data -> external model."""

    def __init__(self):
        super().__init__(
            rule_id="AI-001",
            name="Restricted Data Routed to External Model",
            severity="CRITICAL",
            target_event="AI_DLP_EVALUATION",
            logic="Detects when RESTRICTED or CONFIDENTIAL data is dispatched to an external SaaS or third-party LLM endpoint.",
            evidence_fields=["agent_id", "model_id", "classification", "destination", "is_external_model"],
            false_positive_considerations="Approved enterprise integrations with zero-data-retention SaaS contracts explicitly whitelisted.",
            response_playbook="PB-AI-02-EGRESS-CONTAINMENT",
            validation_scenario="SCN-AI-01-RESTRICTED-DATA-EXTERNAL-MODEL",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type not in (AIEventType.AI_DLP_EVALUATION, AIEventType.AI_DLP_VIOLATION):
            return None
        payload = event.payload
        classification = str(payload.get("classification", "")).upper()
        is_external = payload.get("is_external_model", False) or payload.get("is_external_destination", False)
        if classification in ("RESTRICTED", "CONFIDENTIAL") and is_external:
            return AIDetectionAlert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Agent {event.agent_id} attempted sending {classification} data to external target {payload.get('destination')}.",
                event_id=event.event_id,
                agent_id=event.agent_id,
                model_id=event.model_id,
                evidence=payload,
                response_playbook=self.response_playbook,
            )
        return None


class RuleAI002_AgentUnauthorizedTool(AIDetectionRule):
    """AI-002: Agent -> unauthorized tool."""

    def __init__(self):
        super().__init__(
            rule_id="AI-002",
            name="Agent Unauthorized Tool Invocation",
            severity="HIGH",
            target_event="AI_TOOL_INVOKED",
            logic="Triggers when an AI agent attempts to execute a tool outside its registered capability profile or RBAC grant.",
            evidence_fields=["agent_id", "tool_id", "authorized_tools"],
            false_positive_considerations="Recently added tools where agent capability binding had latency in propagation.",
            response_playbook="PB-AI-01-TOOL-REVOCATION",
            validation_scenario="SCN-AI-04-UNAUTHORIZED-TOOL-CALL",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type != AIEventType.AI_TOOL_INVOKED:
            return None
        payload = event.payload
        if payload.get("is_authorized") is False or payload.get("unauthorized_tool_attempt", False):
            return AIDetectionAlert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Agent {event.agent_id} invoked tool '{payload.get('tool_id')}' without authorization.",
                event_id=event.event_id,
                agent_id=event.agent_id,
                model_id=event.model_id,
                evidence=payload,
                response_playbook=self.response_playbook,
            )
        return None


class RuleAI003_CrossTenantRetrieval(AIDetectionRule):
    """AI-003: Cross-tenant retrieval."""

    def __init__(self):
        super().__init__(
            rule_id="AI-003",
            name="Cross-Tenant Vector Retrieval Violation",
            severity="CRITICAL",
            target_event="AI_RETRIEVAL_EVENT",
            logic="Fires when RAG vector search results cross tenant partition boundaries.",
            evidence_fields=["caller_tenant", "doc_tenants", "vector_collection"],
            false_positive_considerations="Global common reference knowledge bases with explicit multi-tenant grants.",
            response_playbook="PB-AI-03-AGENT-QUARANTINE",
            validation_scenario="SCN-AI-03-CROSS-TENANT-RETRIEVAL",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type != AIEventType.AI_RETRIEVAL_EVENT:
            return None
        payload = event.payload
        if payload.get("cross_scope_detected", False) or payload.get("cross_tenant", False):
            return AIDetectionAlert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Cross-tenant retrieval detected for caller tenant '{payload.get('caller_tenant')}'.",
                event_id=event.event_id,
                agent_id=event.agent_id,
                model_id=event.model_id,
                evidence=payload,
                response_playbook=self.response_playbook,
            )
        return None


class RuleAI004_ModelIntegrityMismatch(AIDetectionRule):
    """AI-004: Model artifact integrity mismatch."""

    def __init__(self):
        super().__init__(
            rule_id="AI-004",
            name="Model Weight / Artifact Hash Mismatch",
            severity="CRITICAL",
            target_event="AI_MODEL_CHANGED",
            logic="Detects hash discrepancies between running model memory/weights and approved golden provenance baseline.",
            evidence_fields=["model_id", "approved_hash", "current_hash"],
            false_positive_considerations="Unannounced emergency hotfix deployed without updating registry first.",
            response_playbook="PB-AI-04-MODEL-ISOLATION",
            validation_scenario="SCN-AI-06-INTEGRITY-COMPROMISE",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type in (AIEventType.AI_MODEL_DEPLOYED, AIEventType.AI_MODEL_CHANGED):
            payload = event.payload
            current_h = payload.get("current_hash") or payload.get("runtime_hash")
            approved_h = payload.get("approved_hash") or payload.get("expected_hash")
            if current_h and approved_h and current_h != approved_h:
                return AIDetectionAlert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Model {event.model_id} artifact hash verification failed against golden baseline.",
                    event_id=event.event_id,
                    agent_id=event.agent_id,
                    model_id=event.model_id,
                    evidence=payload,
                    response_playbook=self.response_playbook,
                )
        return None


class RuleAI005_AgentToolLoopAnomaly(AIDetectionRule):
    """AI-005: Agent tool-loop anomaly."""

    def __init__(self):
        super().__init__(
            rule_id="AI-005",
            name="Autonomous Agent Infinite Tool Loop Detected",
            severity="HIGH",
            target_event="AI_AGENT_ANOMALY",
            logic="Detects runaway autonomous agents repeating identical tool calls or exceeding iteration depth limits.",
            evidence_fields=["agent_id", "step_count", "loop_signature"],
            false_positive_considerations="Legitimate bulk ingestion pipelines configured with high retry count.",
            response_playbook="PB-AI-01-TOOL-REVOCATION",
            validation_scenario="SCN-AI-07-AGENT-LOOP",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type == AIEventType.AI_AGENT_ANOMALY:
            payload = event.payload
            if payload.get("anomaly_type") == "AGENT_LOOP" or payload.get("is_loop", False):
                return AIDetectionAlert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Agent {event.agent_id} detected in infinite tool invocation loop.",
                    event_id=event.event_id,
                    agent_id=event.agent_id,
                    model_id=event.model_id,
                    evidence=payload,
                    response_playbook=self.response_playbook,
                )
        return None


class RuleAI006_UnexpectedModelEgress(AIDetectionRule):
    """AI-006: Unexpected model egress."""

    def __init__(self):
        super().__init__(
            rule_id="AI-006",
            name="Unexpected Model Egress or Data Shadow Dispatch",
            severity="HIGH",
            target_event="AI_EGRESS_BLOCKED",
            logic="Triggers on network connections from model serving infrastructure toward unapproved foreign IP/domain destinations.",
            evidence_fields=["source_model_server", "egress_destination", "bytes_transferred"],
            false_positive_considerations="Telemetry heartbeat or model update mirrors.",
            response_playbook="PB-AI-02-EGRESS-CONTAINMENT",
            validation_scenario="SCN-AI-08-EGRESS-ANOMALY",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type == AIEventType.AI_EGRESS_BLOCKED:
            return AIDetectionAlert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Unexpected model egress toward {event.payload.get('destination')} was intercepted.",
                event_id=event.event_id,
                agent_id=event.agent_id,
                model_id=event.model_id,
                evidence=event.payload,
                response_playbook=self.response_playbook,
            )
        return None


class RuleAI007_SecretDetectedInPrompt(AIDetectionRule):
    """AI-007: Secret detected in prompt."""

    def __init__(self):
        super().__init__(
            rule_id="AI-007",
            name="Credential or Secret Ingested in Model Prompt",
            severity="CRITICAL",
            target_event="AI_PROMPT_BLOCKED",
            logic="Detects high-entropy secrets (API keys, private tokens, passwords) submitted inside prompts.",
            evidence_fields=["caller_identity", "secret_type", "prompt_hash"],
            false_positive_considerations="Mock API keys in unit test prompts or synthetic documentation.",
            response_playbook="PB-AI-03-AGENT-QUARANTINE",
            validation_scenario="SCN-AI-02-PROMPT-INJECTION-AND-SECRETS",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type in (AIEventType.AI_PROMPT_SCANNED, AIEventType.AI_PROMPT_BLOCKED):
            payload = event.payload
            if payload.get("secret_detected", False) or payload.get("secret_count", 0) > 0:
                return AIDetectionAlert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Secret detected in prompt from {event.user_id or event.agent_id} (types: {payload.get('secret_types')}).",
                    event_id=event.event_id,
                    agent_id=event.agent_id,
                    model_id=event.model_id,
                    evidence=payload,
                    response_playbook=self.response_playbook,
                )
        return None


class RuleAI008_RestrictedDocUnauthorizedAgent(AIDetectionRule):
    """AI-008: Restricted document retrieved by unauthorized agent."""

    def __init__(self):
        super().__init__(
            rule_id="AI-008",
            name="Restricted Knowledge Base Chunk Retrieved by Unauthorized Agent",
            severity="HIGH",
            target_event="AI_RETRIEVAL_EVENT",
            logic="Detects vector search retrieval yielding RESTRICTED/CONFIDENTIAL chunks where agent lacks specific data authorization tag.",
            evidence_fields=["agent_id", "kb_id", "doc_id", "doc_classification", "agent_clearance"],
            false_positive_considerations="Agent granted temporary emergency clearance not yet reflected in static ACL cache.",
            response_playbook="PB-AI-01-TOOL-REVOCATION",
            validation_scenario="SCN-AI-05-UNAUTHORIZED-DATA-READ",
        )

    def evaluate(self, event: AISecurityEvent) -> Optional[AIDetectionAlert]:
        if event.event_type == AIEventType.AI_RETRIEVAL_EVENT:
            payload = event.payload
            if payload.get("authorization_failed", False) or payload.get("unauthorized_classification", False):
                return AIDetectionAlert(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Agent {event.agent_id} attempted unauthorized retrieval of restricted chunk {payload.get('chunk_id')}.",
                    event_id=event.event_id,
                    agent_id=event.agent_id,
                    model_id=event.model_id,
                    evidence=payload,
                    response_playbook=self.response_playbook,
                )
        return None
