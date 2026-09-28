"""Tests for Phase 30 Agent and Tool Security.
Covers: Agent registry, effective permissions, least privilege tool contracts, tool interception, behavior analytics, and runtime monitoring.
"""
import pytest
from ai_security.inventory.assets import DeploymentEnvironment
from ai_security.agents.registry import AgentRegistry, AIAgentRecord
from ai_security.agents.identity import AgentIdentityManager, AgentIdentityBinding
from ai_security.agents.permissions import AgentPermissionEvaluator
from ai_security.agents.runtime import AgentRuntimeMonitor, AgentRuntimeStep
from ai_security.agents.behavior import AgentBehaviorAnalytics, AgentAnomalyType
from ai_security.tools.registry import AIToolRegistry, AIToolRecord, ToolType, ToolRiskLevel
from ai_security.tools.authorization import ToolAuthorizationEngine, ToolPermissionContract
from ai_security.tools.invocation import ToolInvocationInterceptor


def test_agent_registry_and_identity_binding():
    registry = AgentRegistry()
    agent41 = registry.get_agent("AGENT-41")
    assert agent41 is not None
    assert agent41.model_id == "MODEL-781"
    assert "database_query" in agent41.tools
    assert "http_post" in agent41.tools
    assert agent41.identity_id == "SERVICE-IDENTITY-77"

    # Register a new agent
    custom_agent = AIAgentRecord(
        agent_id="AGENT-REPORT-01",
        name="Quarterly Report Bot",
        owner="finance-ops",
        model_id="MODEL-781",
        identity_id="SERVICE-IDENTITY-99",
        tools=["internal_pdf_gen"],
        data_sources=["KB-001"],
        system_policy="Read only reporting agent",
        risk_level="LOW",
    )
    registry.register_agent(custom_agent)
    assert registry.get_agent("AGENT-REPORT-01") is not None

    # Test AgentIdentityManager
    id_mgr = AgentIdentityManager()
    binding = id_mgr.get_binding("AGENT-41")
    assert binding is not None
    assert binding.service_identity_id == "SERVICE-IDENTITY-77"
    assert binding.cluster_id == "k8s-prod-cluster-01"


def test_effective_agent_access_evaluation():
    agent_reg = AgentRegistry()
    evaluator = AgentPermissionEvaluator(agent_registry=agent_reg)

    report = evaluator.evaluate_effective_access("AGENT-41")
    assert report is not None
    assert report.agent_id == "AGENT-41"
    assert report.has_external_network_tool is True
    assert report.restricted_data_paths_count == 2
    assert "HIGH RISK" in report.risk_assessment
    assert "HTTP tool" in report.highest_risk_capability

    # Evaluate agent with no restricted data
    safe_agent = AIAgentRecord(
        agent_id="AGENT-SAFE",
        name="Safe Search Agent",
        owner="corp-it",
        model_id="MODEL-781",
        identity_id="ID-SAFE",
        tools=["search_kb"],
        data_sources=["KB-001"],
        system_policy="Standard",
        risk_level="LOW",
    )
    agent_reg.register_agent(safe_agent)
    safe_report = evaluator.evaluate_effective_access("AGENT-SAFE")
    assert safe_report.has_external_network_tool is False
    assert safe_report.restricted_data_paths_count == 0
    assert "STANDARD" in safe_report.risk_assessment


def test_tool_registry_and_risk_levels():
    registry = AIToolRegistry()
    tools = registry.list_tools()
    assert len(tools) >= 4

    db_tool = registry.get_tool("database_query")
    assert db_tool is not None
    assert db_tool.tool_type == ToolType.DATABASE_QUERY
    assert db_tool.risk_level == ToolRiskLevel.HIGH

    http_tool = registry.get_tool("http_post")
    assert http_tool is not None
    assert http_tool.risk_level == ToolRiskLevel.HIGH

    # Register a dangerous shell tool
    shell_tool = AIToolRecord(
        tool_id="bash_exec",
        name="Bash Command Execution Tool",
        tool_type=ToolType.SHELL_EXECUTION,
        risk_level=ToolRiskLevel.CRITICAL,
        description="Allows arbitrary command execution on host",
        requires_approval=True,
    )
    registry.register_tool(shell_tool)
    assert registry.get_tool("bash_exec").requires_approval is True


def test_tool_authorization_contracts_least_privilege():
    engine = ToolAuthorizationEngine()

    # 1. Allowed SELECT on analytics
    allowed_db = engine.authorize_invocation(
        agent_id="AGENT-41",
        tool_id="database_query",
        action="SELECT",
        target_resource="analytics_reporting",
    )
    assert allowed_db is True

    # 2. Denied UPDATE action (not permitted in contract)
    denied_action = engine.authorize_invocation(
        agent_id="AGENT-41",
        tool_id="database_query",
        action="DROP",
        target_resource="analytics_reporting",
    )
    assert denied_action is False

    # 3. Denied explicit resource (customer_vault is denied in contract)
    denied_resource = engine.authorize_invocation(
        agent_id="AGENT-41",
        tool_id="database_query",
        action="SELECT",
        target_resource="customer_vault",
    )
    assert denied_resource is False

    # 4. Denied external HTTP resource
    denied_http = engine.authorize_invocation(
        agent_id="AGENT-41",
        tool_id="http_post",
        action="POST",
        target_resource="https://unapproved.external.io/exfiltrate",
    )
    assert denied_http is False


def test_tool_invocation_interceptor_audits():
    interceptor = ToolInvocationInterceptor()

    # Successful authorized invocation
    audit_ok = interceptor.intercept_call(
        agent_id="AGENT-41",
        tool_id="database_query",
        action="SELECT",
        target_resource="analytics_reporting",
        parameters_summary="SELECT count(*) FROM daily_metrics",
    )
    assert audit_ok.is_authorized is True
    assert audit_ok.status == "EXECUTED"

    # Blocked unauthorized resource invocation
    audit_blocked = interceptor.intercept_call(
        agent_id="AGENT-41",
        tool_id="database_query",
        action="SELECT",
        target_resource="customer_vault",
        parameters_summary="SELECT ssn, pan, credit_card FROM customer_vault",
    )
    assert audit_blocked.is_authorized is False
    assert audit_blocked.status == "BLOCKED"
    assert "DENIED" in audit_blocked.reason

    # Blocked unregistered tool invocation
    audit_unreg = interceptor.intercept_call(
        agent_id="AGENT-41",
        tool_id="unregistered_tool_xyz",
        action="RUN",
        target_resource="system",
    )
    assert audit_unreg.status == "BLOCKED"

    audits = interceptor.list_audits()
    assert len(audits) == 3


def test_agent_behavior_analytics_anomaly_and_loop_detection():
    analytics = AgentBehaviorAnalytics()

    # Normal activity baseline: db_queries=2, http_calls=0, max_iterations=10
    normal_findings = analytics.evaluate_agent_activity(
        agent_id="AGENT-41",
        observed_db_queries=2,
        observed_http_calls=0,
        observed_iterations=3,
    )
    assert len(normal_findings) == 0

    # Anomalous activity: db_queries=18, http_calls=7 (Section 30.80 Step 4 scenario)
    anom_findings = analytics.evaluate_agent_activity(
        agent_id="AGENT-41",
        observed_db_queries=18,
        observed_http_calls=7,
        observed_iterations=5,
    )
    assert len(anom_findings) >= 1
    types = [f.anomaly_type for f in anom_findings]
    assert AgentAnomalyType.AI_BEHAVIOR_ANOMALY in types
    finding = anom_findings[0]
    assert finding.severity == "HIGH"
    assert "18 DB queries" in finding.description
    assert "7 external HTTP calls" in finding.description

    # Tool loop anomaly: iterations=37 (Section 30.51 scenario: max_tool_calls=10, observed=37)
    loop_findings = analytics.evaluate_agent_activity(
        agent_id="AGENT-41",
        observed_db_queries=1,
        observed_http_calls=0,
        observed_iterations=37,
    )
    assert len(loop_findings) == 1
    assert loop_findings[0].anomaly_type == AgentAnomalyType.TOOL_LOOP_ANOMALY
    assert "exceeded maximum iteration threshold" in loop_findings[0].description


def test_agent_runtime_monitor_steps():
    from ai_security.agents.runtime import AgentExecutionStepType
    monitor = AgentRuntimeMonitor()
    monitor.record_step(
        AgentRuntimeStep(
            step_id="STEP-1",
            agent_id="AGENT-41",
            step_type=AgentExecutionStepType.AGENT_START,
            action_name="init",
            target_resource="agent_env",
            payload_summary="Agent initialized for session SES-101",
            duration_ms=12.5,
        )
    )
    monitor.record_step(
        AgentRuntimeStep(
            step_id="STEP-2",
            agent_id="AGENT-41",
            step_type=AgentExecutionStepType.RETRIEVAL_QUERY,
            action_name="retrieve",
            target_resource="KB-001",
            payload_summary="Retrieved 3 chunks from KB-001",
            duration_ms=45.0,
        )
    )
    monitor.record_step(
        AgentRuntimeStep(
            step_id="STEP-3",
            agent_id="AGENT-41",
            step_type=AgentExecutionStepType.TOOL_INVOCATION,
            action_name="query_db",
            target_resource="analytics_reporting",
            payload_summary="Executed database query on analytics_reporting",
            duration_ms=88.2,
        )
    )

    steps = monitor.get_agent_history("AGENT-41")
    assert len(steps) == 3
    assert steps[0].step_type == AgentExecutionStepType.AGENT_START
    assert steps[1].step_type == AgentExecutionStepType.RETRIEVAL_QUERY
    assert steps[2].step_type == AgentExecutionStepType.TOOL_INVOCATION
    assert monitor.count_tool_calls_in_session("AGENT-41") == 1

