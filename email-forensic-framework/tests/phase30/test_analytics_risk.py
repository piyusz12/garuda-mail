"""Tests for Phase 30 AI Analytics, Anomaly Detection, and Multi-Dimensional Risk Scoring.
Covers: Tool loop anomaly detection, token surges, and decoupled risk dimensions (Model, Data, Agent, Tool, Network, Supply Chain, Privacy).
"""
import pytest
from ai_security.analytics.anomalies import AIAnomalyDetector, AIAnomalyCategory
from ai_security.risk.data import AIRiskEngine, AIRiskProfile
from ai_security.agents.registry import AIAgentRecord


def test_ai_anomaly_detection_loops_and_tokens():
    detector = AIAnomalyDetector(loop_threshold=10, token_surge_threshold=8000)

    # 1. Normal tool execution
    normal_loop = detector.inspect_agent_execution(agent_id="AGENT-41", tool_iterations=4)
    assert normal_loop is None

    # 2. Section 30.51 scenario: Agent unintentionally loops 37 times (exceeds threshold 10)
    anom_loop = detector.inspect_agent_execution(agent_id="AGENT-41", tool_iterations=37)
    assert anom_loop is not None
    assert anom_loop.category == AIAnomalyCategory.AGENT_LOOP
    assert anom_loop.severity == "HIGH"
    assert anom_loop.evidence["iterations"] == 37
    assert "repeated tool execution 37 times" in anom_loop.description

    # 3. Normal token usage
    normal_token = detector.inspect_token_usage(caller_id="USER-1192", token_count=1200)
    assert normal_token is None

    # 4. Token surge anomaly
    anom_token = detector.inspect_token_usage(caller_id="USER-1192", token_count=16500)
    assert anom_token is not None
    assert anom_token.category == AIAnomalyCategory.TOKEN_ANOMALY
    assert anom_token.severity == "MEDIUM"
    assert anom_token.evidence["token_count"] == 16500


def test_multi_dimensional_risk_scoring_decoupled():
    risk_engine = AIRiskEngine()

    # High-risk agent: AGENT-41 with DB tool, HTTP post, and RESTRICTED DATA-8821
    agent41 = AIAgentRecord(
        agent_id="AGENT-41",
        name="customer-assistant-agent",
        owner="customer-platform",
        model_id="MODEL-781",
        identity_id="SERVICE-IDENTITY-77",
        tools=["database_query", "search_kb", "http_post"],
        data_sources=["DATA-8821", "VECTOR-DB-07"],
        system_policy="Assist customer platform inquiries within least-privilege boundary.",
    )

    profile41 = risk_engine.evaluate_agent_risk(agent41)
    assert profile41.asset_id == "AGENT-41"
    assert profile41.composite_risk_rating in ("HIGH", "CRITICAL")

    # Verify all 7 risk dimensions are preserved separately (Section 30.49)
    assert profile41.model_risk_score == 25.0
    assert profile41.data_risk_score >= 80.0
    assert profile41.tool_risk_score >= 80.0
    assert profile41.network_risk_score >= 70.0
    assert profile41.supply_chain_risk_score == 20.0
    assert profile41.privacy_risk_score >= 80.0
    assert profile41.agent_risk_score >= 70.0

    assert len(profile41.risk_factors) >= 2
    assert any("External HTTP tool" in rf for rf in profile41.risk_factors)
    assert any("RESTRICTED" in rf for rf in profile41.risk_factors)

    # Low-risk agent: Safe internal reporting agent
    safe_agent = AIAgentRecord(
        agent_id="AGENT-SAFE-01",
        name="internal-docs-indexer",
        owner="corp-it",
        model_id="MODEL-781",
        identity_id="SERVICE-SAFE",
        tools=["search_kb"],
        data_sources=["KB-001"],
        system_policy="Internal search only.",
    )
    safe_profile = risk_engine.evaluate_agent_risk(safe_agent)
    assert safe_profile.composite_risk_rating == "LOW"
    assert safe_profile.network_risk_score == 15.0
    assert safe_profile.privacy_risk_score == 20.0
    assert len(safe_profile.risk_factors) == 0
