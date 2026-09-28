"""Unit tests for Phase 30 Section 30.38 / 30.80 Step 7 (Incident Playbooks),
30.43 / 30.44 (Governance & Deprecation), and 30.50 / 30.71 (Sovereign AI).
"""
import pytest
import time

from ai_security.agents.registry import AgentRegistry
from ai_security.models.registry import AIModelRegistry, ModelLifecycleStatus
from ai_security.incident import (
    AIIncidentDispatcher,
    ToolRevocationPlaybook,
    EgressContainmentPlaybook,
    AgentQuarantinePlaybook,
    ModelIsolationPlaybook,
)
from ai_security.governance import (
    AIGovernanceManager,
    AIGovernanceRecord,
    AIRiskTier,
)
from ai_security.sovereignty import (
    SovereignAIChecker,
    SovereigntyComponentSpec,
    HostingEnvironmentType,
)


def test_incident_response_tool_revocation_precision():
    agent_reg = AgentRegistry()
    agent = agent_reg.get_agent("AGENT-41")
    assert "http_post" in agent.tools
    assert "database_query" in agent.tools

    dispatcher = AIIncidentDispatcher(agent_registry=agent_reg)
    case = dispatcher.create_case(
        title="Restricted Exfiltration Attempt by AGENT-41",
        severity="CRITICAL",
        trigger_rule="AI-001",
        agent_id="AGENT-41",
        case_id="CASE-9001",
    )
    assert case.status == "OPEN"

    # Execute PB-AI-01-TOOL-REVOCATION
    res = dispatcher.execute_playbook(
        "PB-AI-01-TOOL-REVOCATION",
        {"agent_id": "AGENT-41", "tool_id": "http_post"},
        case_id="CASE-9001",
    )

    assert res.status == "SUCCESS"
    assert res.details["revoked_tool"] == "http_post"
    assert "http_post" not in agent.tools
    # Precision containment: harmless database query remains functional
    assert "database_query" in agent.tools
    assert case.status == "CONTAINED"
    assert len(case.playbook_results) == 1


def test_incident_response_egress_and_agent_quarantine():
    agent_reg = AgentRegistry()
    model_reg = AIModelRegistry()
    dispatcher = AIIncidentDispatcher(agent_reg, model_reg)

    # Test Egress Containment
    res_egress = dispatcher.execute_playbook(
        "PB-AI-02-EGRESS-CONTAINMENT",
        {"agent_id": "AGENT-41", "destination": "malicious.external.net"},
    )
    assert res_egress.status == "SUCCESS"
    assert res_egress.details["blocked_destination"] == "malicious.external.net"

    # Test Model Isolation
    res_model = dispatcher.execute_playbook(
        "PB-AI-04-MODEL-ISOLATION",
        {"model_id": "MODEL-781", "fallback_model": "MODEL-APPROVED-FALLBACK"},
    )
    assert res_model.status == "SUCCESS"
    m = model_reg.get_model("MODEL-781")
    assert m.lifecycle_status == ModelLifecycleStatus.BLOCKED

    # Test Agent Quarantine
    res_quar = dispatcher.execute_playbook(
        "PB-AI-03-AGENT-QUARANTINE",
        {"agent_id": "AGENT-DEV-BOT"},
    )
    assert res_quar.status == "SUCCESS"
    agent = agent_reg.get_agent("AGENT-DEV-BOT")
    assert agent.is_active is False


def test_ai_governance_and_model_deprecation():
    gov_mgr = AIGovernanceManager()
    rec = gov_mgr.get_record("MODEL-781")
    assert rec is not None
    assert rec.owner == "secops-ai-team@garuda.internal"
    assert rec.risk_tier == AIRiskTier.TIER_2_HIGH
    assert not rec.is_review_overdue()

    # Evaluate deprecation of legacy model
    report = gov_mgr.evaluate_model_deprecation("MODEL-101-LEGACY", ModelLifecycleStatus.DEPRECATED)
    assert report.is_deprecated_or_blocked is True
    assert "legacy-billing-app" in report.dependent_applications
    assert "AGENT-LEGACY-09" in report.dependent_agents
    assert report.recommended_replacement_model == "MODEL-781"
    assert report.migration_deadline is not None


def test_sovereign_ai_security_and_air_gap_verification():
    checker = SovereignAIChecker(target_sovereignty_jurisdiction="IN")

    # Air-gapped fully sovereign on-prem pipeline
    sovereign_components = [
        SovereigntyComponentSpec("LOCAL-LLM-01", "MODEL", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
        SovereigntyComponentSpec("LOCAL-EMBED-01", "EMBEDDING", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
        SovereigntyComponentSpec("LOCAL-VDB-01", "VECTOR_DB", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
    ]

    report = checker.evaluate_pipeline("SYS-AIR-GAP-CLEARED", sovereign_components, require_air_gap=True)
    assert report.is_sovereign_compliant is True
    assert report.is_fully_air_gapped is True
    assert report.sovereignty_score_pct == 100.0
    assert len(report.violations) == 0

    # Non-sovereign pipeline with foreign SaaS and internet egress
    leaky_components = [
        SovereigntyComponentSpec("FOREIGN-LLM-01", "MODEL", HostingEnvironmentType.EXTERNAL_SAAS, "US", True, False),
        SovereigntyComponentSpec("LOCAL-VDB-01", "VECTOR_DB", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
    ]

    leaky_report = checker.evaluate_pipeline("SYS-FOREIGN-CLOUD", leaky_components, require_air_gap=True)
    assert leaky_report.is_sovereign_compliant is False
    assert leaky_report.is_fully_air_gapped is False
    assert leaky_report.sovereignty_score_pct < 60.0
    assert len(leaky_report.violations) >= 2
