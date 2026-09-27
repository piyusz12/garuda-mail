"""
Phase 24 — Incident Management Unit Tests
Tests Incident models, lifecycle state transitions, closure guardrails, triage enrichment, and priority assignment.
"""

import pytest
from incident.models import Incident, IncidentStatus, IncidentSeverity, IncidentPriority
from incident.triage import IncidentTriageEngine
from incident.priority import PriorityEngine
from incident.lifecycle import IncidentLifecycleManager, LifecycleTransitionError
from incident.manager import IncidentManager


def test_incident_creation_and_triage():
    mgr = IncidentManager()
    inc = mgr.create_incident(
        title="TLS Regression on Core Inbound Gateway",
        description="Observed TLS 1.0 sessions on MTA-07",
        severity=IncidentSeverity.HIGH,
        affected_assets=["MTA-07", "MTA-01"],
        detections=["DET-TLS-001"]
    )

    assert inc.incident_id.startswith("INC-")
    assert inc.status == IncidentStatus.TRIAGED
    assert inc.triage_data["asset_criticality"] == "CRITICAL"
    assert inc.triage_data["historical_recurrence"] is True
    assert inc.priority in [IncidentPriority.P1_CRITICAL, IncidentPriority.P2_HIGH]
    assert len(inc.timeline) >= 3


def test_invalid_lifecycle_transition():
    inc = Incident(
        incident_id="INC-TEST-01",
        title="Test Incident",
        description="Testing invalid status jump",
        severity=IncidentSeverity.MEDIUM,
        priority=IncidentPriority.P3_MEDIUM,
        status=IncidentStatus.NEW,
        affected_assets=["MTA-03"]
    )

    # NEW cannot transition directly to RESOLVED
    with pytest.raises(LifecycleTransitionError):
        IncidentLifecycleManager.transition(inc, IncidentStatus.RESOLVED)


def test_closure_requires_evidence_and_verification():
    inc = Incident(
        incident_id="INC-TEST-02",
        title="Unverified Closure Test",
        description="Testing closure guardrail",
        severity=IncidentSeverity.LOW,
        priority=IncidentPriority.P4_LOW,
        status=IncidentStatus.MONITORING,
        affected_assets=["MTA-08"]
    )

    # Fails because evidence is not preserved
    with pytest.raises(LifecycleTransitionError, match="evidence has not been preserved"):
        IncidentLifecycleManager.transition(inc, IncidentStatus.RESOLVED)

    inc.add_evidence("SESSION", "FLOW-99", "A" * 64)

    # Fails because REMEDIATION_VERIFIED event is missing
    with pytest.raises(LifecycleTransitionError, match="not been verified against telemetry"):
        IncidentLifecycleManager.transition(inc, IncidentStatus.RESOLVED)

    inc.add_timeline_event("REMEDIATION_VERIFIED", "Telemetry clean")
    # Now allowed
    IncidentLifecycleManager.transition(inc, IncidentStatus.RESOLVED)
    assert inc.status == IncidentStatus.RESOLVED


def test_automated_reopening_on_recurrence():
    mgr = IncidentManager()
    orig = mgr.create_incident(
        title="Plaintext AUTH on Port 25",
        description="Cleartext credentials observed",
        severity=IncidentSeverity.HIGH,
        affected_assets=["MTA-04"]
    )
    orig.add_evidence("SESSION", "FLOW-101", "B" * 64)
    orig.add_timeline_event("REMEDIATION_VERIFIED", "Telemetry clean")
    IncidentLifecycleManager.transition(orig, IncidentStatus.REMEDIATION)
    IncidentLifecycleManager.transition(orig, IncidentStatus.VERIFICATION)
    IncidentLifecycleManager.transition(orig, IncidentStatus.RECOVERY)
    IncidentLifecycleManager.transition(orig, IncidentStatus.MONITORING)
    IncidentLifecycleManager.transition(orig, IncidentStatus.RESOLVED)

    # Reopen
    reopened = mgr.reopen_incident(orig.incident_id, "New plain AUTH observed on port 25")
    assert reopened.linked_incident_id == orig.incident_id
    assert reopened.status == IncidentStatus.REOPENED
    assert reopened.reopened_count == 1
    assert orig.reopened_count == 1
