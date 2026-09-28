"""Tests for Phase 30 Forensics, Control Validation, AI Digital Twin, and AI Copilot.
Covers: Forensic snapshots, chronological timelines, scenario runners, graph attack-path traversal, digital twin simulation, and copilot queries.
"""
import pytest
from ai_security.forensics.snapshots import AIForensicSnapshot, AIForensicSnapshotManager
from ai_security.forensics.timeline import AITimelineBuilder, AITimelineEntry
from ai_security.forensics.evidence import AIEvidencePackage
from ai_security.validation.scenarios import AIScenarioCatalog
from ai_security.validation.runner import AISecurityValidationRunner
from ai_graph.traversal import AIGraph
from ai_security.copilot.investigations import AISecurityCopilot


def test_ai_forensic_snapshots_and_immutable_hash():
    snapshot = AIForensicSnapshot(
        snapshot_id="SNAP-TEST-001",
        agent_id="AGENT-41",
        model_id="MODEL-781",
        identity_id="SERVICE-IDENTITY-77",
        prompt_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        retrieved_documents=["DOC-CHUNK-8821"],
        tool_calls=["database_query", "http_post"],
        destination_target="https://external.analytics.io",
        dlp_action="BLOCK",
    )

    digest = snapshot.compute_hash()
    assert len(digest) == 64
    assert digest == snapshot.compute_hash()  # Deterministic

    # Test snapshot manager
    mgr = AIForensicSnapshotManager()
    mgr.save_snapshot(snapshot)
    retrieved = mgr.get_snapshot("SNAP-TEST-001")
    assert retrieved is not None
    assert retrieved.model_id == "MODEL-781"


def test_ai_timeline_builder_and_evidence_package():
    # Build Section 30.81 timeline
    timeline = AITimelineBuilder.build_incident_timeline(
        agent_id="AGENT-41",
        model_id="MODEL-781",
        destination="external.example",
    )
    assert len(timeline) == 9
    assert timeline[0].time_str == "14:21:00"
    assert timeline[0].actor == "AGENT-41"
    assert timeline[4].event_category == "TOOL"
    assert timeline[5].event_category == "DLP"
    assert timeline[6].event_category == "RESPONSE"
    assert timeline[8].event_category == "FORENSICS"

    # Package into immutable evidence package
    snapshot = AIForensicSnapshot(
        snapshot_id="SNAP-CASE-9001",
        agent_id="AGENT-41",
        model_id="MODEL-781",
        identity_id="SERVICE-IDENTITY-77",
        prompt_hash="sha256:abc123",
        retrieved_documents=["DOC-8821"],
        tool_calls=["http_post"],
        destination_target="external.example",
        dlp_action="BLOCK",
    )

    pkg = AIEvidencePackage(
        case_id="CASE-9001",
        agent_id="AGENT-41",
        snapshot=snapshot,
        timeline=timeline,
        findings=[{"type": "AI_BEHAVIOR_ANOMALY", "severity": "HIGH"}],
    )
    pkg_hash = pkg.finalize()
    assert len(pkg_hash) == 64
    assert pkg.package_sha256 == pkg_hash
    d = pkg.to_dict()
    assert d["case_id"] == "CASE-9001"
    assert len(d["timeline"]) == 9


def test_ai_security_validation_runner():
    runner = AISecurityValidationRunner()
    results = runner.run_all_standard_tests()
    assert len(results) >= 3

    for res in results:
        assert res.is_passed is True
        assert res.evidence_ref != ""
        assert res.expected_outcome == res.observed_outcome


def test_ai_graph_attack_path_and_digital_twin_simulation():
    graph = AIGraph()

    # 1. Verify attack path discovery
    egress_paths = graph.find_ai_data_egress_paths()
    assert len(egress_paths) >= 1

    first_path = egress_paths[0]
    assert first_path["attack_path_type"] == "AI DATA EGRESS PATH"
    assert first_path["agent_id"] == "AGENT-41"
    assert first_path["risk_level"] == "CRITICAL"
    assert "AGENT-41" in first_path["path"]["chain_description"]
    assert "external.example" in first_path["path"]["chain_description"]

    # 2. Digital Twin simulation (Section 30.65): What happens if HTTP tool is removed?
    sim_result = graph.simulate_twin_containment(revoked_tool="http_post")
    assert sim_result["simulation"] == "DIGITAL_TWIN_CONTAINMENT"
    assert sim_result["revoked_tool"] == "http_post"
    assert sim_result["containment_effective"] is True
    assert sim_result["remaining_egress_paths_count"] == 0
    assert "keeping database_query and RAG operational" in sim_result["impact_summary"]


def test_ai_security_copilot_queries_and_dashboard():
    copilot = AISecurityCopilot()

    # 1. Section 30.63 query: "What can Agent-41 access?"
    access_info = copilot.ask_what_can_agent_access("AGENT-41")
    assert access_info["agent"] == "AGENT-41"
    assert access_info["model"] == "MODEL-781"
    assert "database_query" in access_info["tools"]
    assert "http_post" in access_info["tools"]
    assert access_info["external_network"] == "Enabled"
    assert "HTTP tool" in access_info["highest_risk_capability"]

    # 2. Section 30.64 query: "Why was this AI request blocked?"
    blocked_info = copilot.ask_why_request_blocked("REQ-991", "AGENT-41", "RESTRICTED-DATA-8821")
    assert blocked_info["decision"] == "BLOCK"
    assert blocked_info["policy"] == "AI-DLP-01-BLOCK-RESTRICTED-EGRESS"
    assert len(blocked_info["evidence"]) >= 4

    # 3. Section 30.77 dashboard metrics
    dashboard = copilot.get_dashboard_summary()
    assert dashboard.total_ai_assets == 1284
    assert dashboard.models_count == 184
    assert dashboard.agents_count == 73
    assert dashboard.rag_pipelines_count == 42
    assert dashboard.tools_count == 118
    assert dashboard.blocked_ai_egress_count == 12
