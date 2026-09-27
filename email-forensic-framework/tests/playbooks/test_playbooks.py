"""
Phase 24 — Playbooks Unit Tests
Tests Playbook registry loading, selection, regression comparisons, and adaptive maturity.
"""

from playbooks.models import Playbook, PlaybookMaturity
from playbooks.registry import PlaybookRegistry
from playbooks.engine import PlaybookEngine
from incident.models import Incident, IncidentStatus, IncidentSeverity, IncidentPriority


def test_playbook_registry_and_selection():
    registry = PlaybookRegistry()
    assert "CRYPTO-REGRESSION-001" in registry.playbooks
    assert "CERT-COMPROMISE-002" in registry.playbooks
    assert "SUSPICIOUS-JA4-005" in registry.playbooks

    engine = PlaybookEngine(registry)
    inc = Incident(
        incident_id="INC-TLS",
        title="TLS 1.0 Downgrade Detected",
        description="Legacy TLS seen",
        severity=IncidentSeverity.HIGH,
        priority=IncidentPriority.P2_HIGH,
        status=IncidentStatus.TRIAGED,
        affected_assets=["MTA-07"],
        detections=["DET-TLS-001"]
    )
    pb = engine.select_playbook_for_incident(inc)
    assert pb.playbook_id == "CRYPTO-REGRESSION-001"


def test_playbook_regression_testing():
    registry = PlaybookRegistry()
    engine = PlaybookEngine(registry)
    pb1 = registry.get_playbook("CRYPTO-REGRESSION-001")
    pb2 = Playbook(
        playbook_id="CRYPTO-REGRESSION-001",
        name=pb1.name,
        version="2.2",
        maturity=PlaybookMaturity.CANARY_AUTOMATION,
        trigger=pb1.trigger,
        preconditions=pb1.preconditions,
        investigation_steps=pb1.investigation_steps,
        containment_steps=pb1.containment_steps,
        remediation_steps=pb1.remediation_steps,
        verification_steps=pb1.verification_steps,
        rollback_steps=pb1.rollback_steps,
        closure_conditions=pb1.closure_conditions,
        historical_rollback_rate=0.01,
        execution_count=55
    )

    inc = Incident(
        incident_id="INC-HIST",
        title="Historical TLS Regression",
        description="Test",
        severity=IncidentSeverity.HIGH,
        priority=IncidentPriority.P2_HIGH,
        status=IncidentStatus.TRIAGED,
        affected_assets=["MTA-07"]
    )

    res = engine.regression_test_playbooks(pb1, pb2, inc)
    assert res["passed_regression"] is True
    assert res["v2_rollback_rate"] < res["v1_rollback_rate"]
    assert res["recommended_version"] == "2.2"


def test_adaptive_tuning_recommendation():
    registry = PlaybookRegistry()
    engine = PlaybookEngine(registry)
    rec = engine.recommend_adaptive_tuning("CRYPTO-REGRESSION-001")
    assert "CANARY_AUTOMATION" in rec["recommended_maturity"]
