"""Unit tests for Phase 30 Section 30.74 (Event Bus), 30.82 (Threat Hunting),
and 30.83 (Detection Engineering).
"""
import pytest
import time

from ai_security.events import (
    AIEventType,
    AISecurityEvent,
    AISecurityEventBus,
)
from ai_security.hunting import (
    AIHuntEngine,
    SensitiveAccessExternalToolHunt,
    ModelArtifactHashTamperHunt,
    ToolCallRateAnomalyHunt,
    CrossScopeRAGRetrievalHunt,
)
from ai_security.detections import (
    AIDetectionEngine,
    RuleAI001_RestrictedDataExternalModel,
    RuleAI002_AgentUnauthorizedTool,
    RuleAI003_CrossTenantRetrieval,
    RuleAI004_ModelIntegrityMismatch,
    RuleAI005_AgentToolLoopAnomaly,
    RuleAI006_UnexpectedModelEgress,
    RuleAI007_SecretDetectedInPrompt,
    RuleAI008_RestrictedDocUnauthorizedAgent,
)


def test_ai_security_event_bus():
    bus = AISecurityEventBus()
    bus.clear()

    received = []
    bus.subscribe(AIEventType.AI_TOOL_INVOKED, lambda ev: received.append(ev))

    ev1 = bus.publish(
        AIEventType.AI_TOOL_INVOKED,
        {"tool_name": "database_query", "query": "SELECT * FROM customers"},
        agent_id="AGENT-41",
    )
    ev2 = bus.publish(
        AIEventType.AI_MODEL_DISCOVERED,
        {"model_name": "llama-3-8b"},
        model_id="MODEL-01",
    )

    assert bus.count() == 2
    assert len(received) == 1
    assert received[0].event_id == ev1.event_id
    assert received[0].agent_id == "AGENT-41"
    assert ev1.event_hash != ""

    filtered = bus.get_events(event_types=[AIEventType.AI_TOOL_INVOKED], agent_id="AGENT-41")
    assert len(filtered) == 1
    assert filtered[0].payload["tool_name"] == "database_query"


def test_threat_hunting_sensitive_access_external_tool():
    hunt = SensitiveAccessExternalToolHunt(time_window_seconds=300.0)
    now = time.time()

    events = [
        AISecurityEvent(
            event_id="EVT-01",
            event_type=AIEventType.AI_RETRIEVAL_EVENT,
            timestamp=now,
            agent_id="AGENT-41",
            payload={"classification": "RESTRICTED", "chunk_id": "CHUNK-101"},
        ),
        AISecurityEvent(
            event_id="EVT-02",
            event_type=AIEventType.AI_TOOL_INVOKED,
            timestamp=now + 12.0,  # 12s later
            agent_id="AGENT-41",
            payload={"tool_name": "http_post", "is_external": True, "destination": "external.exfil.org"},
        ),
    ]

    findings = hunt.execute(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.hunt_id == "AI-HUNT-001"
    assert f.severity == "CRITICAL"
    assert f.agent_id == "AGENT-41"
    assert "exfiltration" in f.title.lower()
    assert f.evidence["time_delta_seconds"] == pytest.approx(12.0)


def test_threat_hunting_model_artifact_tamper():
    hunt = ModelArtifactHashTamperHunt()
    events = [
        AISecurityEvent(
            event_id="EVT-MOD-1",
            event_type=AIEventType.AI_MODEL_CHANGED,
            timestamp=time.time(),
            model_id="MODEL-781",
            payload={
                "approved_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "current_hash": "bad0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b999",
            },
        )
    ]
    findings = hunt.execute(events)
    assert len(findings) == 1
    assert findings[0].hunt_id == "AI-HUNT-002"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].model_id == "MODEL-781"


def test_threat_hunting_tool_call_rate_anomaly():
    hunt = ToolCallRateAnomalyHunt(spike_multiplier=3.0, min_calls=5)
    events = []
    for i in range(12):
        events.append(
            AISecurityEvent(
                event_id=f"EVT-TC-{i}",
                event_type=AIEventType.AI_TOOL_INVOKED,
                timestamp=time.time() + i,
                agent_id="AGENT-RUNAWAY",
                payload={"tool_name": "api_fetch", "baseline_rate": 2.0},
            )
        )
    findings = hunt.execute(events)
    assert len(findings) == 1
    assert findings[0].hunt_id == "AI-HUNT-003"
    assert findings[0].evidence["observed_tool_calls"] == 12


def test_threat_hunting_cross_scope_retrieval():
    hunt = CrossScopeRAGRetrievalHunt()
    events = [
        AISecurityEvent(
            event_id="EVT-RAG-1",
            event_type=AIEventType.AI_RETRIEVAL_EVENT,
            timestamp=time.time(),
            agent_id="AGENT-41",
            payload={"caller_tenant": "TENANT-ALPHA", "doc_tenants": ["TENANT-ALPHA", "TENANT-BETA"]},
        )
    ]
    findings = hunt.execute(events)
    assert len(findings) == 1
    assert findings[0].hunt_id == "AI-HUNT-004"
    assert "TENANT-BETA" in findings[0].evidence["cross_tenants"]


def test_detection_engine_rules_ai001_to_ai008():
    engine = AIDetectionEngine()
    assert len(engine.list_rules()) == 8

    # AI-001: Restricted data to external model
    ev_001 = AISecurityEvent(
        event_id="EV-1",
        event_type=AIEventType.AI_DLP_EVALUATION,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"classification": "RESTRICTED", "destination": "api.openai.com", "is_external_model": True},
    )
    alerts_001 = engine.evaluate_event(ev_001)
    assert len(alerts_001) == 1
    assert alerts_001[0].rule_id == "AI-001"
    assert alerts_001[0].severity == "CRITICAL"
    assert alerts_001[0].response_playbook == "PB-AI-02-EGRESS-CONTAINMENT"

    # AI-002: Agent unauthorized tool
    ev_002 = AISecurityEvent(
        event_id="EV-2",
        event_type=AIEventType.AI_TOOL_INVOKED,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"tool_id": "shell_exec", "is_authorized": False},
    )
    alerts_002 = engine.evaluate_event(ev_002)
    assert len(alerts_002) == 1
    assert alerts_002[0].rule_id == "AI-002"
    assert alerts_002[0].severity == "HIGH"

    # AI-003: Cross-tenant retrieval
    ev_003 = AISecurityEvent(
        event_id="EV-3",
        event_type=AIEventType.AI_RETRIEVAL_EVENT,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"caller_tenant": "TENANT-A", "cross_tenant": True},
    )
    alerts_003 = engine.evaluate_event(ev_003)
    assert len(alerts_003) == 1
    assert alerts_003[0].rule_id == "AI-003"

    # AI-004: Model artifact integrity mismatch
    ev_004 = AISecurityEvent(
        event_id="EV-4",
        event_type=AIEventType.AI_MODEL_CHANGED,
        timestamp=time.time(),
        model_id="MODEL-781",
        payload={"approved_hash": "hash_a", "current_hash": "hash_b"},
    )
    alerts_004 = engine.evaluate_event(ev_004)
    assert len(alerts_004) == 1
    assert alerts_004[0].rule_id == "AI-004"

    # AI-005: Agent tool loop anomaly
    ev_005 = AISecurityEvent(
        event_id="EV-5",
        event_type=AIEventType.AI_AGENT_ANOMALY,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"anomaly_type": "AGENT_LOOP", "is_loop": True},
    )
    alerts_005 = engine.evaluate_event(ev_005)
    assert len(alerts_005) == 1
    assert alerts_005[0].rule_id == "AI-005"

    # AI-006: Unexpected model egress
    ev_006 = AISecurityEvent(
        event_id="EV-6",
        event_type=AIEventType.AI_EGRESS_BLOCKED,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"destination": "unapproved.external.io"},
    )
    alerts_006 = engine.evaluate_event(ev_006)
    assert len(alerts_006) == 1
    assert alerts_006[0].rule_id == "AI-006"

    # AI-007: Secret detected in prompt
    ev_007 = AISecurityEvent(
        event_id="EV-7",
        event_type=AIEventType.AI_PROMPT_BLOCKED,
        timestamp=time.time(),
        user_id="USER-1192",
        payload={"secret_detected": True, "secret_count": 1, "secret_types": ["OPENAI_API_KEY"]},
    )
    alerts_007 = engine.evaluate_event(ev_007)
    assert len(alerts_007) == 1
    assert alerts_007[0].rule_id == "AI-007"

    # AI-008: Restricted document retrieved by unauthorized agent
    ev_008 = AISecurityEvent(
        event_id="EV-8",
        event_type=AIEventType.AI_RETRIEVAL_EVENT,
        timestamp=time.time(),
        agent_id="AGENT-41",
        payload={"authorization_failed": True, "chunk_id": "RESTRICTED-CHUNK-99"},
    )
    alerts_008 = engine.evaluate_event(ev_008)
    assert len(alerts_008) == 1
    assert alerts_008[0].rule_id == "AI-008"

    assert len(engine.list_alerts()) == 8
