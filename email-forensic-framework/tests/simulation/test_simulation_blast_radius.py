"""
Phase 24 — Simulation & Blast Radius Unit Tests
Tests BlastRadiusCalculator graph traversal, DigitalTwinSimulator compatibility scoring, and DryRunEngine.
"""

from simulation.blast_radius import BlastRadiusCalculator
from simulation.digital_twin import DigitalTwinSimulator
from simulation.dry_run import DryRunEngine
from response.planner import ResponsePlanner
from playbooks.registry import PlaybookRegistry
from incident.models import Incident, IncidentStatus, IncidentSeverity, IncidentPriority


def test_blast_radius_calculation():
    calc = BlastRadiusCalculator()
    report = calc.calculate_blast_radius(["MTA-07", "MTA-01"])
    assert report.total_enterprise_assets >= 7
    assert report.blast_radius_ratio > 0.25
    assert report.risk_level in ["HIGH", "CRITICAL"]
    assert report.critical_dependencies_count >= 1
    assert "smtp-out" in report.affected_services


def test_digital_twin_simulation():
    sim = DigitalTwinSimulator()
    res = sim.simulate_action("DISABLE_TLS11", ["MTA-07"])
    assert res.total_simulated_sessions > 1000
    assert res.compatibility_score >= 0.95
    assert res.safe_to_proceed is True
    assert len(res.detailed_observations) >= 2


def test_dry_run_preview():
    pb = PlaybookRegistry().get_playbook("CRYPTO-REGRESSION-001")
    inc = Incident(
        incident_id="INC-DRY",
        title="Test Dry Run",
        description="Dry run verification",
        severity=IncidentSeverity.HIGH,
        priority=IncidentPriority.P2_HIGH,
        status=IncidentStatus.TRIAGED,
        affected_assets=["MTA-07"]
    )
    plan = ResponsePlanner.create_plan_for_incident(inc, pb)
    report = DryRunEngine.execute_dry_run(plan)

    assert len(report.actions_preview) == len(plan.actions)
    assert report.change_records_to_create == 1
    assert report.reversible is True
