"""Tests for DSPM Posture Rules, Drift Detection, DLP Policies, and Enforcement."""

import pytest
from data_security.inventory import DataAsset, DataAssetType, ClassificationLevel
from data_security.posture import (
    DSPMEvaluator,
    DSPMSeverity,
    DataPostureDriftDetector,
)
from data_security.dlp import (
    DLPAction,
    DLPPolicy,
    DLPEnforcementEngine,
)
from data_security.flows import DataMovementEvent, DataFlowChannel


def test_dspm_posture_evaluation():
    """Verify DSPM security posture rules flag unencrypted, public, or unowned sensitive assets."""
    evaluator = DSPMEvaluator()

    # Asset violating multiple DSPM rules:
    # - Sensitive data in public storage (DSPM-003)
    # - Sensitive data without encryption (DSPM-004)
    # - Sensitive data without registered owner (DSPM-001)
    bad_asset = DataAsset(
        data_asset_id="DATA-UNSECURE-01",
        name="public_analytics_dump",
        asset_type=DataAssetType.BUCKET,
        business_owner="unknown",
        location="us-east-1",
        environment="production",
        classification=ClassificationLevel.RESTRICTED,
        sensitivity_score=95.0,
        storage_system="S3",
        encryption_at_rest=False,
        is_publicly_exposed=True,
    )

    findings = evaluator.evaluate_asset(bad_asset)
    rule_ids = [f.rule_id for f in findings]

    assert "DSPM-001" in rule_ids  # Missing owner
    assert "DSPM-003" in rule_ids  # Public exposure
    assert "DSPM-004" in rule_ids  # Unencrypted


def test_posture_drift_detection():
    """Verify detection of state drifts such as encryption disabled or bucket made public."""
    drift_detector = DataPostureDriftDetector()

    initial_state = {
        "encryption_at_rest": True,
        "is_publicly_exposed": False,
        "classification": "RESTRICTED",
    }
    current_state = {
        "encryption_at_rest": False,  # Drifted!
        "is_publicly_exposed": True,   # Drifted!
        "classification": "RESTRICTED",
    }

    drift_detector.set_baseline("DATA-8821", initial_state)
    drifts = drift_detector.check_drift("DATA-8821", current_state)

    assert len(drifts) >= 2
    drift_fields = [d.attribute for d in drifts]
    assert "encryption_at_rest" in drift_fields
    assert "is_publicly_exposed" in drift_fields


def test_dlp_policy_enforcement_and_simulation():
    """Verify explainable DLP decisions: BLOCK on restricted egress, ALLOW on approved internal movement."""
    engine = DLPEnforcementEngine()

    # 1. External transfer of RESTRICTED customer data -> must BLOCK
    malicious_event = DataMovementEvent(
        event_id="FLOW-EV-01",
        source_asset_id="DATA-8821",
        destination_id="external.example",
        channel=DataFlowChannel.API_HTTP,
        workload_id="WORKLOAD-991",
        identity_id="SERVICE-91",
        bytes_transferred=250000000,
        record_count=900000,
        classification=ClassificationLevel.RESTRICTED,
        is_external_destination=True,
    )
    decision = engine.evaluate_flow(malicious_event.to_dict())
    assert decision.action == DLPAction.BLOCK
    assert decision.matched_policy_id == "DLP-01-BLOCK-RESTRICTED-EGRESS"
    assert "prohibited" in decision.reasons[0].lower()
    assert decision.confidence >= 0.95

    # 2. Approved internal transfer of INTERNAL data -> must ALLOW
    internal_event = DataMovementEvent(
        event_id="FLOW-EV-02",
        source_asset_id="DATA-INTERNAL-01",
        destination_id="corp.internal.warehouse",
        channel=DataFlowChannel.DATABASE_EXPORT,
        workload_id="WORKLOAD-ETL-PROD",
        identity_id="SVC-ETL",
        bytes_transferred=100000,
        record_count=1500,
        classification=ClassificationLevel.INTERNAL,
        is_external_destination=False,
    )
    decision_internal = engine.evaluate_flow(internal_event.to_dict())
    assert decision_internal.action == DLPAction.ALLOW

    # 3. Policy Simulation: dry-run test
    simulation_result = engine.simulate_policy(
        policy=DLPPolicy(
            policy_id="DLP-SIM-TEST",
            name="Block all external data flows",
            target_classifications=[ClassificationLevel.RESTRICTED],
            prohibit_external=True,
            action=DLPAction.BLOCK,
        ),
        historical_flows=[malicious_event.to_dict(), internal_event.to_dict()],
    )
    assert simulation_result["historical_flows_evaluated"] == 2
    assert simulation_result["would_block_count"] == 1
    assert "SERVICE-91" in simulation_result["affected_identities"]
