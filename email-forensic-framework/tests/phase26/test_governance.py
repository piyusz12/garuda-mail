"""Tests for Governance, Separation of Duties, Approvals, and Signed Reports."""
import pytest
from validation.governance import (
    SeparationOfDutiesController,
    SeparationOfDutiesViolation,
    ApprovalWorkflowManager,
    ApprovalStatus,
)
from validation.campaigns import (
    CampaignEngine,
    CampaignReportGenerator,
    SignedValidationReport,
)
from validation.range import RangeManager
from validation.scenarios import ScenarioRepository
from validation.execution import ScenarioRunner, KillSwitchManager


def test_separation_of_duties():
    # Low risk allowed
    assert SeparationOfDutiesController.validate_execution_allowed("author1", None, "author1", "LOW") is True

    # High risk requires approver
    with pytest.raises(SeparationOfDutiesViolation):
        SeparationOfDutiesController.validate_execution_allowed("author1", None, "operator1", "HIGH")

    # Author cannot approve their own high risk scenario
    with pytest.raises(SeparationOfDutiesViolation):
        SeparationOfDutiesController.validate_execution_allowed("author1", "author1", "operator1", "HIGH")

    # Approver cannot also operate/execute high risk scenario
    with pytest.raises(SeparationOfDutiesViolation):
        SeparationOfDutiesController.validate_execution_allowed("author1", "approver1", "approver1", "HIGH")

    # Valid multi-party separation
    assert SeparationOfDutiesController.validate_execution_allowed("author1", "approver1", "operator1", "HIGH") is True


def test_approval_workflow():
    mgr = ApprovalWorkflowManager()
    req = mgr.submit_request("SCN-102", "MEDIUM", "author-01")
    assert req.status == ApprovalStatus.PENDING

    decided = mgr.submit_decision(req.request_id, "lead-approver", "APPROVED", "Risk reviewed and range verified.")
    assert decided.status == ApprovalStatus.APPROVED
    assert decided.approver_id == "lead-approver"


def test_signed_validation_report():
    range_mgr = RangeManager()
    runner = ScenarioRunner(range_manager=range_mgr, kill_switch=KillSwitchManager())
    campaign_engine = CampaignEngine(runner=runner)

    scenarios = [ScenarioRepository().get("SCN-101")]
    crun = campaign_engine.execute_campaign("CAMP-TLS-01", scenarios)

    report = CampaignReportGenerator.generate_signed_report(crun)
    assert report.report_id.startswith("REP-")
    assert len(report.digital_signature) == 64  # SHA-256 hex string
    assert len(report.run_hash) == 64
    assert len(report.scenario_hash) == 64
