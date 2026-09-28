"""Tests for Phase 30 AI DLP, AI-SPM Posture Management, and Configuration Drift.
Covers: Explainable AI DLP evaluations, policy simulation, posture benchmark rules, and drift detection.
"""
import pytest
from data_security.inventory.normalization import ClassificationLevel
from ai_security.inventory.assets import AIAsset, AIAssetType, ModelLifecycleStatus, DeploymentEnvironment
from ai_security.dlp.decisions import AIDLPAction
from ai_security.dlp.policies import AIDLPPolicy
from ai_security.dlp.enforcement import AIDLPEnforcementEngine
from ai_security.posture.rules import AISPMRule, AISPMSeverity
from ai_security.posture.evaluation import AISPMEvaluator, AISPMFinding
from ai_security.posture.drift import AIConfigurationDriftDetector


def test_ai_dlp_evaluation_and_blocking():
    engine = AIDLPEnforcementEngine()

    # 1. Block restricted customer data egressing to external destination via tool
    blocked_event = {
        "event_id": "EVT-TEST-001",
        "agent_id": "AGENT-41",
        "source_asset_id": "DATA-8821",
        "classification": "RESTRICTED",
        "is_external": True,
        "is_external_tool": True,
        "destination": "https://external.analytics.io/leak",
        "record_count": 150,
    }
    decision = engine.evaluate_ai_event(blocked_event)
    assert decision.action == AIDLPAction.BLOCK
    assert decision.is_blocked is True
    assert decision.matched_policy_id == "AI-DLP-01-BLOCK-RESTRICTED-EGRESS"
    assert "RESTRICTED" in decision.reasons[0]
    assert decision.confidence == 0.98

    # 2. Allow compliant internal request
    allowed_event = {
        "event_id": "EVT-TEST-002",
        "agent_id": "AGENT-41",
        "source_asset_id": "DATA-INTERNAL-DOCS",
        "classification": "INTERNAL",
        "is_external": False,
        "is_external_tool": False,
        "destination": "internal-model",
        "record_count": 10,
    }
    allowed_decision = engine.evaluate_ai_event(allowed_event)
    assert allowed_decision.action == AIDLPAction.ALLOW
    assert allowed_decision.is_blocked is False

    # 3. Restrict massive bulk transfer exceeding 10k records
    bulk_event = {
        "event_id": "EVT-TEST-003",
        "agent_id": "AGENT-BULK-SYNC",
        "source_asset_id": "DATA-CORP-ARCHIVE",
        "classification": "CONFIDENTIAL",
        "is_external": False,
        "is_external_tool": False,
        "destination": "internal-storage",
        "record_count": 25000,
    }
    bulk_decision = engine.evaluate_ai_event(bulk_event)
    assert bulk_decision.action == AIDLPAction.RESTRICT
    assert bulk_decision.matched_policy_id == "AI-DLP-02-BULK-RESTRICTION"

    decisions = engine.list_decisions()
    assert len(decisions) == 3


def test_ai_dlp_policy_simulation():
    engine = AIDLPEnforcementEngine()

    proposed_policy = AIDLPPolicy(
        policy_id="AI-DLP-SIM-CONFIDENTIAL-BLOCK",
        name="Block External Routing of Confidential AI Data",
        target_classifications=[ClassificationLevel.RESTRICTED, ClassificationLevel.CONFIDENTIAL],
        action=AIDLPAction.BLOCK,
        prohibit_external_model=True,
        prohibit_external_tool=True,
    )

    historical_events = [
        {"event_id": "H1", "agent_id": "AGENT-41", "classification": "RESTRICTED", "is_external": True},
        {"event_id": "H2", "agent_id": "AGENT-DEV-BOT", "classification": "CONFIDENTIAL", "is_external": True},
        {"event_id": "H3", "agent_id": "AGENT-SAFE", "classification": "INTERNAL", "is_external": False},
        {"event_id": "H4", "agent_id": "AGENT-41", "classification": "CONFIDENTIAL", "is_external": True},
    ]

    sim_result = engine.simulate_policy(proposed_policy, historical_events)
    assert sim_result["historical_events_evaluated"] == 4
    assert sim_result["would_block_count"] == 3
    assert sim_result["would_restrict_count"] == 0
    assert "AGENT-41" in sim_result["affected_agents"]
    assert "AGENT-DEV-BOT" in sim_result["affected_agents"]
    assert "AGENT-SAFE" not in sim_result["affected_agents"]


def test_ai_spm_posture_evaluation():
    evaluator = AISPMEvaluator()

    # 1. Unapproved model violation (AI-SPM-001)
    unapproved_model = AIAsset(
        ai_asset_id="MODEL-UNAPPROVED-01",
        name="rogue-llama-shadow",
        asset_type=AIAssetType.LLM,
        owner="shadow-dev",
        environment=DeploymentEnvironment.PRODUCTION,
        provider="unknown",
        version="1.0",
        location="s3://shadow/model",
        status=ModelLifecycleStatus.DISCOVERED,  # Not APPROVED
        risk_level="HIGH",
        metadata={"artifact_hash": "sha256:abc"},
    )
    findings = evaluator.evaluate_asset(unapproved_model)
    rule_ids = [f.rule_id for f in findings]
    assert "AI-SPM-001" in rule_ids

    # 2. Agent with excessive tools violation (AI-SPM-003)
    bloated_agent = AIAsset(
        ai_asset_id="AGENT-OVERPRIVILEGED",
        name="all-powerful-agent",
        asset_type=AIAssetType.AGENT,
        owner="platform",
        environment=DeploymentEnvironment.PRODUCTION,
        provider="garuda-ai",
        version="1.0",
        location="prod-cluster",
        status=ModelLifecycleStatus.ACTIVE,
        risk_level="HIGH",
        metadata={"tools": ["tool1", "tool2", "tool3", "tool4", "tool5"]},
    )
    agent_findings = evaluator.evaluate_asset(bloated_agent)
    agent_rule_ids = [f.rule_id for f in agent_findings]
    assert "AI-SPM-003" in agent_rule_ids

    # 3. Vector store lacking tenant isolation (AI-SPM-006)
    open_vdb = AIAsset(
        ai_asset_id="VECTOR-OPEN",
        name="shared-customer-vectors",
        asset_type=AIAssetType.VECTOR_STORE,
        owner="customer-ops",
        environment=DeploymentEnvironment.PRODUCTION,
        provider="qdrant",
        version="1.8",
        location="vdb-node-01",
        status=ModelLifecycleStatus.ACTIVE,
        risk_level="HIGH",
        metadata={"tenant_isolation": False},
    )
    vdb_findings = evaluator.evaluate_asset(open_vdb)
    vdb_rule_ids = [f.rule_id for f in vdb_findings]
    assert "AI-SPM-006" in vdb_rule_ids


def test_ai_configuration_drift_detection():
    detector = AIConfigurationDriftDetector()

    # Set approved baseline for AGENT-41
    detector.set_baseline(
        "AGENT-41",
        {
            "egress_network_allowed": False,
            "max_tool_iterations": 10,
            "system_prompt_version": "v1.2",
            "artifact_hash": "sha256:4a8b8c2d9e1f",
        },
    )

    # Current configuration with unauthorized network egress and changed prompt
    current_config = {
        "egress_network_allowed": True,  # DRIFT!
        "max_tool_iterations": 10,  # Compliant
        "system_prompt_version": "v2.0-custom",  # DRIFT!
        "artifact_hash": "sha256:4a8b8c2d9e1f",  # Compliant
    }

    drifts = detector.check_drift("AGENT-41", current_config)
    assert len(drifts) == 2

    drift_params = {d.parameter_name: d for d in drifts}
    assert "egress_network_allowed" in drift_params
    assert drift_params["egress_network_allowed"].severity == "CRITICAL"
    assert drift_params["egress_network_allowed"].baseline_value is False
    assert drift_params["egress_network_allowed"].observed_value is True

    assert "system_prompt_version" in drift_params
    assert drift_params["system_prompt_version"].severity == "HIGH"
