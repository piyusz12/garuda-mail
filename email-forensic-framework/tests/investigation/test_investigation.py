"""
Tests for Phase 23 Autonomous Investigation Agent, Playbooks, Cases, Bundles, and Guardrails.
"""
import pytest
from investigation.playbooks import INVESTIGATION_PLAYBOOKS
from investigation.timeline import TimelineBuilder
from investigation.cases import CaseManager
from investigation.bundles import EvidenceBundleBuilder
from investigation.agent import AutonomousInvestigationAgent, InvestigationGuardrailException
from datetime import datetime, timezone

def test_investigation_playbooks():
    assert "PB-CERT-01" in INVESTIGATION_PLAYBOOKS
    pb = INVESTIGATION_PLAYBOOKS["PB-CERT-01"]
    assert len(pb.steps) >= 5

def test_timeline_builder():
    tb = TimelineBuilder()
    tb.add_event(datetime(2026, 9, 28, 1, 0, tzinfo=timezone.utc), "SESSION", "MTA-07", "First event", "EVT-1")
    tb.add_event(datetime(2026, 9, 27, 1, 0, tzinfo=timezone.utc), "CERT", "MTA-07", "Earlier event", "EVT-2")
    events = tb.to_dict_list()
    # Should be sorted chronologically
    assert events[0]["event_type"] == "CERT"
    assert events[1]["event_type"] == "SESSION"

def test_evidence_bundle_integrity_and_replay():
    bundle = EvidenceBundleBuilder.assemble_bundle(
        case_id="CASE-TEST",
        timeline=[{"t": "2026-09-28"}],
        events=[{"event_id": "EVT-01"}],
        certificates=[],
        ja4_records=[],
        detection_results=[],
        lineage_trace={},
        query_def={"query_str": "HUNT test FROM tls_events"}
    )
    assert bundle.verify_integrity() is True
    assert "manifest.json" in bundle.hashes
    assert len(bundle.hashes["manifest.json"]) == 64  # SHA-256 length

    replay_res = EvidenceBundleBuilder.replay_investigation(bundle)
    assert replay_res["replayed"] is True
    assert replay_res["bundle_hashes_verified"] is True

def test_agent_guardrails_enforcement():
    agent = AutonomousInvestigationAgent(data_lake=None)
    
    # Allowed autonomous actions
    agent.enforce_guardrail("READ")
    agent.enforce_guardrail("SEARCH")
    agent.enforce_guardrail("CORRELATE")
    agent.enforce_guardrail("PROPOSE")

    # Restricted actions must raise InvestigationGuardrailException
    with pytest.raises(InvestigationGuardrailException):
        agent.enforce_guardrail("QUARANTINE")

    with pytest.raises(InvestigationGuardrailException):
        agent.enforce_guardrail("BLOCK")

    with pytest.raises(InvestigationGuardrailException):
        agent.enforce_guardrail("DELETE")
