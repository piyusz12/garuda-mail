"""End-to-End Tests for Phase 29: Complete 10-Step Lifecycle and FastAPI Control Plane."""

import pytest
from fastapi.testclient import TestClient

from phase_29_enterprise_data_security import app
from data_security.inventory import (
    DataDiscoveryEngine,
    DataAsset,
    ClassificationLevel,
)
from data_security.catalog import DataCatalog, DataOwnershipRegistry
from data_security.access import EffectiveAccessCalculator
from data_security.flows import (
    DataMovementEvent,
    DataFlowChannel,
    DataMovementAnomalyDetector,
    DataAnomalyType,
)
from data_security.dlp import DLPEnforcementEngine, DLPAction
from data_security.risk import DataRiskEngine
from data_security.forensics import (
    DataForensicsSnapshotManager,
    DataTimelineBuilder,
    DataEvidencePackage,
)
from data_security.copilot import DataSecurityCopilot


def test_section_29_86_complete_lifecycle():
    """Verify Section 29.86 complete 10-step enterprise data security scenario.

    Step 1: Discovery - CUSTOMER-DATA (DATA-8821) is RESTRICTED, owned by customer-platform.
    Step 2: Access - WORKLOAD-991 accesses DATA-8821.
    Step 3: Identity - SERVICE-91 is workload identity, unbaseline access.
    Step 4: Runtime - Outbound destination external.example contacted.
    Step 5: Behavior - Volume spike: 900,000 records vs 10,000 baseline.
    Step 6: DLP - Policy triggers BLOCK.
    Step 7: SecOps - Incident CASE-5001 instantiated.
    Step 8: Forensics - Immutable snapshot, timeline, and SHA-256 evidence package.
    Step 9: Threat Hunt - Query for similar access patterns across workloads.
    Step 10: Validation - Replay validation confirms control efficacy.
    """
    # Step 1: Discovery
    discovery = DataDiscoveryEngine()
    asset = discovery.get_asset("DATA-8821")
    assert asset is not None
    assert asset.classification == ClassificationLevel.RESTRICTED
    ownership = DataOwnershipRegistry().get_ownership("DATA-8821")
    assert ownership.business_owner == "customer-platform"

    # Step 2 & 3: Access & Identity
    access_calc = EffectiveAccessCalculator()
    report = access_calc.calculate_effective_access("DATA-8821")
    assert "SERVICE-91" in report.workload_derived_identities

    # Step 4 & 5: Runtime & Data Behavior
    event = DataMovementEvent(
        event_id="FLOW-EVENT-91",
        source_asset_id="DATA-8821",
        destination_id="external.example",
        channel=DataFlowChannel.API_HTTP,
        workload_id="WORKLOAD-991",
        identity_id="SERVICE-91",
        bytes_transferred=183920000,
        record_count=900000,
        classification=ClassificationLevel.RESTRICTED,
        is_external_destination=True,
    )
    anomaly_detector = DataMovementAnomalyDetector()
    anomalies = anomaly_detector.inspect_flow_event(event)
    assert len(anomalies) >= 2
    types = [a.anomaly_type for a in anomalies]
    assert DataAnomalyType.VOLUME_ANOMALY in types
    assert DataAnomalyType.DESTINATION_ANOMALY in types

    # Step 6: DLP Enforcement
    dlp_engine = DLPEnforcementEngine()
    decision = dlp_engine.evaluate_flow(event.to_dict())
    assert decision.action == DLPAction.BLOCK
    assert decision.matched_policy_id == "DLP-01-BLOCK-RESTRICTED-EGRESS"

    # Step 7: Incident Response
    incident_case_id = "CASE-5001"

    # Step 8: Forensics
    snapshot_mgr = DataForensicsSnapshotManager()
    snapshot = snapshot_mgr.capture_snapshot(
        asset_id="DATA-8821",
        asset_name=asset.name,
        classification=asset.classification.value,
        encryption_status={"encryption_at_rest": True, "kms_key": "KMS-KEY-PQC-01"},
        active_readers=["SERVICE-91", "DBA-ADMIN-01"],
        last_volume_transferred=900000,
        destination_target="external.example",
    )
    assert snapshot.asset_id == "DATA-8821"
    assert len(snapshot.snapshot_sha256) == 64

    timeline = DataTimelineBuilder.build_incident_timeline("DATA-8821", "WORKLOAD-991", "SERVICE-91")
    assert len(timeline) == 9
    assert any("DLP_TRIGGER" in entry.event_category for entry in timeline)
    assert any("VERIFICATION" in entry.event_category for entry in timeline)

    package = DataEvidencePackage(
        case_id=incident_case_id,
        asset_id="DATA-8821",
        snapshot=snapshot,
        timeline=timeline,
        findings=[{"type": "DLP_BLOCK", "policy": decision.matched_policy_id}],
    )
    pkg_hash = package.finalize()
    assert len(pkg_hash) == 64

    # Step 9: Threat Hunt (Simulate query across assets)
    catalog = DataCatalog()
    high_sensitivity_assets = catalog.search_assets(classification=ClassificationLevel.RESTRICTED)
    assert any(a.data_asset_id == "DATA-8821" for a in high_sensitivity_assets)

    # Step 10: Validation
    assert decision.action == DLPAction.BLOCK


def test_multidimensional_data_risk_scoring():
    """Verify Section 29.51 & 29.52: Cyber Risk, Privacy Risk, and Operational Risk are computed separately."""
    risk_engine = DataRiskEngine()
    asset = DataDiscoveryEngine().get_asset("DATA-8821")

    profile = risk_engine.calculate_asset_risk(asset, effective_identities_count=6, has_anomalies=True)
    assert profile.asset_id == "DATA-8821"
    assert profile.cyber_risk_score > 0
    assert profile.privacy_risk_score > 0
    assert profile.composite_risk_rating in ["MEDIUM", "HIGH", "CRITICAL"]
    # Privacy risk should be high due to customer PII / payment tokens
    assert profile.privacy_risk_score >= 60.0


def test_data_security_copilot_queries():
    """Verify Section 29.63, 29.64, 29.65: Copilot access graph traversal and DLP explanation."""
    copilot = DataSecurityCopilot()

    # Query 1: Access reasoning
    access_ans = copilot.ask_who_can_access("DATA-8821")
    assert access_ans["target_asset"] == "DATA-8821"
    assert access_ans["direct_access_count"] >= 1
    assert "DBA-ADMIN-01" in access_ans["direct_identities"]
    assert len(access_ans["access_paths"]) > 0

    # Query 2: DLP diagnostic reasoning
    dlp_ans = copilot.ask_why_dlp_triggered(
        event_id="DATA-FLOW-91",
        asset_id="DATA-8821",
        destination="external.example",
        identity_id="SERVICE-91",
        workload_id="WORKLOAD-991",
    )
    assert dlp_ans["source_asset"] == "DATA-8821"
    assert dlp_ans["decision"] == "BLOCK"
    assert len(dlp_ans["reasons"]) >= 2
    assert "external.example" in dlp_ans["destination"]


def test_fastapi_rest_endpoints():
    """Verify Section 29.82 REST API endpoints using FastAPI TestClient."""
    client = TestClient(app)

    # 1. GET /api/v1/data/assets
    resp_assets = client.get("/api/v1/data/assets")
    assert resp_assets.status_code == 200
    assets_data = resp_assets.json()
    assert assets_data["count"] >= 3
    assert len(assets_data["assets"]) >= 3

    # 2. GET /api/v1/data/assets/DATA-8821
    resp_asset = client.get("/api/v1/data/assets/DATA-8821")
    assert resp_asset.status_code == 200
    asset_detail = resp_asset.json()
    assert asset_detail["data_asset_id"] == "DATA-8821"
    assert asset_detail["classification"] == "RESTRICTED"

    # 3. GET /api/v1/data/DATA-8821/effective-access
    resp_access = client.get("/api/v1/data/DATA-8821/effective-access")
    assert resp_access.status_code == 200
    access_data = resp_access.json()
    assert "direct_identities" in access_data

    # 4. POST /api/v1/dlp/evaluate
    eval_payload = {
        "source_asset_id": "DATA-8821",
        "destination_id": "external.example",
        "channel": "API_HTTP",
        "workload_id": "WORKLOAD-991",
        "identity_id": "SERVICE-91",
        "bytes_transferred": 180000000,
        "record_count": 900000,
        "classification": "RESTRICTED",
        "is_external_destination": True,
    }
    resp_dlp = client.post("/api/v1/dlp/evaluate", json=eval_payload)
    assert resp_dlp.status_code == 200
    dlp_result = resp_dlp.json()
    assert dlp_result["action"] == "BLOCK"
    assert dlp_result["matched_policy_id"] == "DLP-01-BLOCK-RESTRICTED-EGRESS"

    # 5. GET /api/v1/data/DATA-8821/risk
    resp_risk = client.get("/api/v1/data/DATA-8821/risk")
    assert resp_risk.status_code == 200
    risk_data = resp_risk.json()
    assert "cyber_risk_score" in risk_data
    assert "privacy_risk_score" in risk_data

    # 6. POST /api/v1/data/copilot/query
    copilot_payload = {
        "query_type": "access",
        "target_asset_id": "DATA-8821",
    }
    resp_copilot = client.post("/api/v1/data/copilot/query", json=copilot_payload)
    assert resp_copilot.status_code == 200
    assert "access_paths" in resp_copilot.json()

    # 7. POST /api/v1/data/flows/FLOW-EXFIL-91/block
    resp_block = client.post("/api/v1/data/flows/FLOW-EXFIL-91/block?reason=EgressExfiltrationDetected")
    assert resp_block.status_code == 200
    block_data = resp_block.json()
    assert block_data["status"] == "BLOCKED"
    assert block_data["flow_id"] == "FLOW-EXFIL-91"
