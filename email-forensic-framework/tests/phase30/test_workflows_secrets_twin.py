"""Unit tests for Phase 30 Section 30.28-30.30 (AI Workflow Security),
30.33 (AI Secrets Security), and 30.47 / 30.65 (AI Digital Twin & Attack Paths).
"""
import pytest

from ai_security.workflows import (
    WorkflowStageType,
    WorkflowStageRecord,
    AIWorkflowChain,
    AIWorkflowManager,
)
from ai_security.secrets import (
    AISecretsScanner,
    SecretAction,
    SecretType,
)
from ai_security.twin import (
    AIDigitalTwin,
)
from data_security.inventory.normalization import ClassificationLevel


def test_ai_workflow_chain_classification_and_access():
    mgr = AIWorkflowManager()
    wf = mgr.get_workflow("WF-CUSTOMER-SUPPORT")
    assert wf is not None
    assert len(wf.stages) == 6

    # Normal public or internal input passes
    eval_ok = wf.validate_execution(ClassificationLevel.INTERNAL)
    assert eval_ok.is_allowed is True
    assert eval_ok.blocked_stage_id is None

    # AI-to-Database policy check: attempt restricted table query
    eval_db_blocked = wf.validate_execution(
        input_classification=ClassificationLevel.INTERNAL,
        target_db_tables=["customer_pii_vault"],
    )
    assert eval_db_blocked.is_allowed is False
    assert "Database policy" in eval_db_blocked.reason

    # AI-to-API policy check: attempt external API call with restricted data
    # Create custom workflow with API stage
    custom_wf = AIWorkflowChain("WF-EXPORT", "Export Workflow", "AGENT-41")
    custom_wf.add_stage(WorkflowStageRecord("S1", WorkflowStageType.INPUT, "In", "in", [ClassificationLevel.RESTRICTED]))
    custom_wf.add_stage(WorkflowStageRecord("S2", WorkflowStageType.API, "Outbound API", "api", [ClassificationLevel.RESTRICTED]))

    eval_api_blocked = custom_wf.validate_execution(
        input_classification=ClassificationLevel.RESTRICTED,
        target_api_endpoints=["https://api.external.untrusted.com/v1/export"],
    )
    assert eval_api_blocked.is_allowed is False
    assert "AI-to-API policy" in eval_api_blocked.reason


def test_ai_secrets_scanner_detection_and_redaction():
    scanner = AISecretsScanner(default_action=SecretAction.BLOCK)

    prompt_with_secrets = (
        "Please use my OpenAI key sk-1234567890abcdef1234567890abcdef12345678 and "
        "AWS key AKIAIOSFODNN7EXAMPLE to fetch my user profile."
    )

    res = scanner.scan(prompt_with_secrets)
    assert res.has_secret is True
    assert res.action == SecretAction.BLOCK
    assert len(res.secrets_found) == 2

    types_found = {s.secret_type for s in res.secrets_found}
    assert SecretType.OPENAI_API_KEY in types_found
    assert SecretType.AWS_ACCESS_KEY in types_found

    # Redaction verification
    assert "sk-1234" in res.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in res.sanitized_text
    assert "***" in res.sanitized_text

    # Benign prompt
    benign_res = scanner.scan("Summarize our quarterly performance report for 2026.")
    assert benign_res.has_secret is False
    assert benign_res.action == SecretAction.ALLOW
    assert len(benign_res.secrets_found) == 0


def test_ai_digital_twin_attack_paths_and_simulation():
    twin = AIDigitalTwin()
    paths = twin.discover_ai_attack_paths()
    assert len(paths) >= 1

    # Check attack path properties
    canonical = paths[0]
    assert canonical.criticality == "CRITICAL"
    assert len(canonical.nodes) > 3

    # Simulate precision tool revocation (PB-AI-01: revoke http_post)
    sim_result = twin.simulate_tool_revocation("AGENT-41", "http_post")
    assert sim_result.simulation_id.startswith("SIM-")
    assert sim_result.severed_paths_count >= 1
    assert sim_result.blast_radius_reduction_pct > 0.0
    assert sim_result.critical_business_impact is False
    assert "eliminated" in sim_result.summary

    # Simulate restricted data access block
    sim_data = twin.simulate_deny_restricted_data_access("AGENT-41", "RESTRICTED")
    assert sim_data.severed_paths_count >= 1
    assert sim_data.blast_radius_reduction_pct > 0.0
