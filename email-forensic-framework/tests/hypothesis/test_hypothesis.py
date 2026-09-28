"""
Tests for Phase 23 Autonomous Hypothesis Generation, Evidence Collection, and Counter-Evidence.
"""
import pytest
from hypothesis.generator import HypothesisGenerator, Hypothesis
from hypothesis.counterevidence import CounterEvidenceEngine
from hypothesis.tester import HypothesisTester
from hunting.engine import HuntCandidate
from datetime import datetime, timezone

def test_hypothesis_generation():
    cand = HuntCandidate(
        candidate_id="CAND-01",
        hunt_id="test_hunt",
        asset_id="MTA-07",
        timestamp=datetime.now(timezone.utc),
        evidence_data={},
        risk_context={"ja4_fingerprint": "JA4-ROGUE"},
        confidence=0.75
    )
    hyp = HypothesisGenerator.generate_from_candidate(cand)
    assert hyp.status == "OPEN"
    assert "JA4-ROGUE" in hyp.statement
    assert "MTA-07" in hyp.target_assets

def test_counter_evidence_evaluation():
    # Test case 1: Known vendor fingerprint
    statements, factor = CounterEvidenceEngine.evaluate_counter_evidence(
        lakehouse=None,
        asset_id="MTA-07",
        ja4_fingerprint="JA4-POSTFIX-OFFICIAL"
    )
    assert len(statements) > 0
    assert factor >= 0.50

    # Test case 2: Approved deployment
    statements2, factor2 = CounterEvidenceEngine.evaluate_counter_evidence(
        lakehouse=None,
        asset_id="MTA-07",
        ja4_fingerprint="JA4-UNKNOWN",
        approved_deployments=[{"asset": "MTA-07", "change_id": "CHG-102", "status": "APPROVED"}]
    )
    assert factor2 >= 0.40

def test_hypothesis_tester():
    hyp = Hypothesis(
        hypothesis_id="HYP-TEST",
        statement="Suspicious client on MTA-07",
        status="OPEN",
        target_assets=["MTA-07"],
        entities={"asset": "MTA-07", "ja4": "JA4-ROGUE"}
    )
    tested = HypothesisTester.test_hypothesis(
        hypothesis=hyp,
        lakehouse=None,
        approved_deployments=[],
        known_vendor_fingerprints=[]
    )
    assert tested.status in ("SUPPORTED", "UNSUPPORTED", "RESOLVED")
    assert "net_confidence" in tested.decomposed_confidence
