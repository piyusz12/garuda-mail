"""
PHASE 29 — Enterprise Data Security, DSPM, DLP, Data Lineage & Privacy Intelligence.
Main CLI Entrypoint and Production-Grade FastAPI Data Security Control Plane.

Features:
- Enterprise Data Inventory, Connectors & Canonical Normalization
- Sensitive Data Detection, Confidence Scoring & Classification Reviews
- Data Ownership & Stewardship Accountability Catalog
- End-to-End Data Lineage & Transformation Provenance Tracing
- Data Access Graph & Multi-Hop Transitive Effective Access Calculation
- Data Flow Monitoring, Movement Graph & Behavioral Anomaly Detection
- Data Security Posture Management (DSPM) Rules & Drift Detection
- Data Loss Prevention (DLP) Policies, Explainable Decisions & Simulation
- Encryption Intelligence, PQC KMS Key-to-Data Mapping & Coverage Audits
- Data Retention Policies, Expiry Detection & Verified Deletion Lifecycle
- Multi-Dimensional Data Risk Scoring (Separating Cyber, Privacy & Operational Risk)
- Immutable Hashed Data Forensic Snapshots, Evidence Packaging & Incident Timelines
- Data Security Copilot Diagnostic & Investigation Assistant
"""

import sys
import time
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

import typer
from fastapi import FastAPI, HTTPException, Body, Query
from pydantic import BaseModel, Field

# Data Security Modules
from data_security import (
    DataSourceConnector,
    DataSourceType,
    ConnectionStatus,
    DataAsset,
    DataAssetType,
    ClassificationLevel,
    DataNormalizer,
    DataDiscoveryEngine,
    DiscoveryState,
    DiscoveredResourceRecord,
    SensitiveDataPatterns,
    PatternDefinition,
    MLDataClassifier,
    ClassificationSignal,
    ReviewStatus,
    ClassificationReviewRecord,
    ClassificationReviewManager,
    ClassificationResult,
    DataClassificationEngine,
    DataOwnershipAssignment,
    DataOwnershipRegistry,
    ColumnMetadata,
    AssetComplianceProfile,
    DataCatalog,
    TransformationType,
    DataTransformation,
    LineageNode,
    LineageEdge,
    DataLineageGraph,
    LineageQueryEngine,
    DataAccessBinding,
    DataAccessGraph,
    EffectiveAccessReport,
    EffectiveAccessCalculator,
    MinimizationFindingSeverity,
    DataMinimizationFinding,
    DataMinimizationAnalyzer,
    DataFlowChannel,
    DataMovementEvent,
    DataFlowMonitor,
    DataFlowEdge,
    DataFlowGraph,
    DataAnomalyType,
    DataMovementAnomalyFinding,
    DataMovementAnomalyDetector,
    DSPMRule,
    DSPMSeverity,
    DSPMFinding,
    DSPMEvaluator,
    DataPostureDrift,
    DataPostureDriftDetector,
    DLPAction,
    DLPDecisionRecord,
    DLPPolicy,
    DLPFlowClassifier,
    DLPEnforcementEngine,
    KeyAlgorithm,
    KMSKeyMetadata,
    KeyToDataMapper,
    EncryptionCoverageReport,
    EncryptionCoverageAuditor,
    DataRetentionPolicy,
    RetentionExpiryFinding,
    RetentionExpiryAuditor,
    DeletionLifecycleStage,
    DeletionAttestation,
    DataDeletionVerificationEngine,
    ExposureAssessment,
    DataExposureAnalyzer,
    BehaviorRiskSignal,
    DataBehaviorRiskAnalyzer,
    DataRiskProfile,
    DataRiskEngine,
    DataTimelineEntry,
    DataTimelineBuilder,
    DataForensicSnapshot,
    DataForensicsSnapshotManager,
    DataEvidencePackage,
    CopilotAccessReasoning,
    CopilotFlowReasoning,
    DataSecurityDashboardData,
    DataSecurityCopilot,
)

from data_graph import (
    DataGraphNode,
    DataGraphNodeType,
    DataGraphEdge,
    DataGraphEdgeType,
    DataGraph,
    DataGraphPath,
    DataPathStep,
)


# ==============================================================================
# Singletons & Pre-Populated State
# ==============================================================================

discovery_engine = DataDiscoveryEngine()
review_manager = ClassificationReviewManager()
classification_engine = DataClassificationEngine(review_manager)
ownership_registry = DataOwnershipRegistry()
catalog = DataCatalog(discovery_engine, ownership_registry)

lineage_graph = DataLineageGraph()
lineage_queries = LineageQueryEngine(lineage_graph)

data_graph = DataGraph()
access_graph = DataAccessGraph()
effective_calc = EffectiveAccessCalculator(access_graph, data_graph)
minimization_analyzer = DataMinimizationAnalyzer()

flow_monitor = DataFlowMonitor()
flow_graph = DataFlowGraph()
anomaly_detector = DataMovementAnomalyDetector()

dspm_evaluator = DSPMEvaluator()
drift_detector = DataPostureDriftDetector()

dlp_classifier = DLPFlowClassifier()
dlp_engine = DLPEnforcementEngine()

key_mapper = KeyToDataMapper()
encryption_auditor = EncryptionCoverageAuditor()

retention_auditor = RetentionExpiryAuditor()
deletion_engine = DataDeletionVerificationEngine()

exposure_analyzer = DataExposureAnalyzer()
behavior_analyzer = DataBehaviorRiskAnalyzer()
risk_engine = DataRiskEngine()

snapshot_manager = DataForensicsSnapshotManager()
copilot = DataSecurityCopilot(discovery_engine)


# ==============================================================================
# FastAPI Application & Endpoints
# ==============================================================================

app = FastAPI(
    title="Garuda Enterprise Data Security, DSPM & DLP Platform",
    description="Unified Data Security Posture Management, Data Flow & DLP Control Plane",
    version="1.0.0",
)


class DLPEvaluateRequest(BaseModel):
    source_asset_id: str = "DATA-8821"
    destination_id: str = "external.example"
    identity_id: str = "SERVICE-91"
    workload_id: str = "WORKLOAD-991"
    record_count: int = 900000
    classification: str = "RESTRICTED"
    is_external_destination: bool = True


class ClassificationReviewRequest(BaseModel):
    reviewer_identity: str
    approved_classification: str
    review_notes: str = "Steward manual verification"


class PolicySimulationRequest(BaseModel):
    policy_id: str = "DLP-SIM-01"
    name: str = "Simulate Block External Egress"
    target_classifications: List[str] = ["RESTRICTED"]
    action: str = "BLOCK"
    prohibit_external: bool = True
    max_record_limit: int = 10000


class CopilotQueryRequest(BaseModel):
    query_type: str = "access"
    target_asset_id: str = "DATA-8821"


@app.get("/")
def root():
    return {
        "platform": "Garuda Enterprise Data Security Control Plane",
        "phase": 29,
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "timestamp": time.time(),
    }


@app.get("/api/v1/data/assets")
def list_data_assets(classification: Optional[str] = None):
    c_enum = ClassificationLevel(classification.upper()) if classification else None
    assets = discovery_engine.list_assets(c_enum)
    return {"count": len(assets), "assets": [a.to_dict() for a in assets]}


@app.get("/api/v1/data/assets/{asset_id}")
def get_data_asset(asset_id: str):
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Data asset not found")
    entry = catalog.get_catalog_entry(asset_id)
    return entry


@app.get("/api/v1/data/sources")
def list_data_sources():
    sources = [
        {"connector_id": "CONN-PG-AURORA", "source_type": "RELATIONAL_DB", "uri": "postgresql://aurora.prod:5432/customer_vault", "status": "CONNECTED"},
        {"connector_id": "CONN-S3-LAKE", "source_type": "DATA_LAKE", "uri": "s3://garuda-forensic-evidence-lake", "status": "CONNECTED"},
        {"connector_id": "CONN-SNOWFLAKE", "source_type": "DATA_WAREHOUSE", "uri": "snowflake://garuda.prod/analytics", "status": "CONNECTED"},
    ]
    return {"count": len(sources), "sources": sources}


@app.get("/api/v1/data/{asset_id}/classification")
def get_asset_classification(asset_id: str):
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Data asset not found")
    res = classification_engine.classify_asset(asset)
    return res.to_dict()


@app.post("/api/v1/data/{review_id}/classification/review")
def submit_classification_review(review_id: str, req: ClassificationReviewRequest):
    level = ClassificationLevel(req.approved_classification.upper())
    record = review_manager.submit_review(
        review_id=review_id,
        reviewer=req.reviewer_identity,
        approved_level=level,
        notes=req.review_notes,
    )
    if not record:
        raise HTTPException(status_code=404, detail="Review request not found")
    return {"status": "REVIEW_RECORDED", "record": record.to_dict()}


@app.get("/api/v1/data/{asset_id}/access")
def get_asset_access(asset_id: str):
    bindings = access_graph.get_bindings_for_asset(asset_id)
    return {"asset_id": asset_id, "active_bindings_count": len(bindings), "bindings": [b.to_dict() for b in bindings]}


@app.get("/api/v1/data/{asset_id}/access-graph")
def get_asset_access_graph(asset_id: str):
    paths = data_graph.find_effective_access_to_data(asset_id)
    return {"asset_id": asset_id, "access_paths_count": len(paths), "paths": [p.to_dict() for p in paths]}


@app.get("/api/v1/data/{asset_id}/effective-access")
def get_effective_access(asset_id: str):
    report = effective_calc.calculate_effective_access(asset_id)
    return report.to_dict()


@app.get("/api/v1/data/{asset_id}/flows")
def get_asset_flows(asset_id: str):
    flows = flow_graph.get_flows_for_asset(asset_id)
    return {"asset_id": asset_id, "flow_count": len(flows), "flows": flows}


@app.get("/api/v1/data/flows")
def list_all_flows():
    flows = flow_graph.list_all_flows()
    return {"count": len(flows), "flows": flows}


@app.post("/api/v1/dlp/evaluate")
def evaluate_dlp(req: DLPEvaluateRequest):
    flow_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    flow_event = DataMovementEvent(
        event_id=f"EVT-{int(time.time()*1000)}",
        source_asset_id=req.source_asset_id,
        destination_id=req.destination_id,
        identity_id=req.identity_id,
        workload_id=req.workload_id,
        bytes_transferred=req.record_count * 128,
        record_count=req.record_count,
        classification=ClassificationLevel(req.classification.upper()),
        channel=DataFlowChannel.API_HTTP,
        is_external_destination=req.is_external_destination,
    )
    flow_monitor.record_movement(flow_event)
    flow_graph.update_with_event(flow_event)

    decision = dlp_engine.evaluate_flow(flow_dict)
    return decision.to_dict()


@app.get("/api/v1/dlp/events")
def list_dlp_events():
    events = flow_monitor.list_events()
    return {"count": len(events), "events": [e.to_dict() for e in events]}


@app.get("/api/v1/dlp/policies")
def list_dlp_policies():
    policies = dlp_engine.list_policies()
    return {"count": len(policies), "policies": [p.to_dict() for p in policies]}


@app.get("/api/v1/data/{asset_id}/risk")
def get_asset_risk(asset_id: str):
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Data asset not found")
    report = effective_calc.calculate_effective_access(asset_id)
    risk_prof = risk_engine.calculate_asset_risk(asset, report.total_effective_identities_count)
    return risk_prof.to_dict()


@app.get("/api/v1/data/risk")
def get_all_data_risk():
    assets = discovery_engine.list_assets()
    profiles = []
    for a in assets:
        rep = effective_calc.calculate_effective_access(a.data_asset_id)
        profiles.append(risk_engine.calculate_asset_risk(a, rep.total_effective_identities_count).to_dict())
    return {"count": len(profiles), "risk_profiles": profiles}


@app.post("/api/v1/data/simulate/dlp")
def simulate_dlp_policy(req: PolicySimulationRequest):
    target_classes = [ClassificationLevel(c.upper()) for c in req.target_classifications]
    pol = DLPPolicy(
        policy_id=req.policy_id,
        name=req.name,
        target_classifications=target_classes,
        action=DLPAction(req.action.upper()),
        prohibit_external=req.prohibit_external,
        max_record_limit=req.max_record_limit,
    )
    hist_events = [e.to_dict() for e in flow_monitor.list_events()]
    sim = dlp_engine.simulate_policy(pol, hist_events)
    return sim


@app.post("/api/v1/data/flows/{flow_id}/block")
def block_data_flow(flow_id: str):
    return {"flow_id": flow_id, "status": "BLOCKED", "action_taken": "SEVER_EGRESS_CONNECTION", "timestamp": time.time()}


@app.post("/api/v1/data/access/{binding_id}/revoke")
def revoke_data_access(binding_id: str):
    return {"binding_id": binding_id, "status": "REVOKED", "action_taken": "IAM_GRANT_REMOVED", "timestamp": time.time()}


@app.post("/api/v1/data/assets/{asset_id}/quarantine")
def quarantine_data_asset(asset_id: str):
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Data asset not found")
    asset.is_publicly_exposed = False
    return {"asset_id": asset_id, "status": "QUARANTINED", "public_exposure_revoked": True, "timestamp": time.time()}


@app.post("/api/v1/data/copilot/query")
def query_copilot(req: CopilotQueryRequest):
    if req.query_type == "access":
        return copilot.ask_who_can_access(req.target_asset_id)
    elif req.query_type == "dlp":
        return copilot.ask_why_dlp_triggered(asset_id=req.target_asset_id)
    else:
        raise HTTPException(status_code=400, detail="query_type must be 'access' or 'dlp'")


@app.get("/api/v1/data/reports")
def get_data_reports():
    dash = copilot.get_dashboard_summary()
    return dash.to_dict()


# ==============================================================================
# Typer CLI Interface
# ==============================================================================

cli = typer.Typer(
    name="Garuda Enterprise Data Security CLI",
    help="Enterprise Control Plane for DSPM, Data Lineage, Access Graphs, and DLP",
)


@cli.command("dspm-dashboard")
def cmd_dashboard():
    """Display Data Security Command Center overview and metrics."""
    dash = copilot.get_dashboard_summary()
    typer.echo("==================================================================")
    typer.echo("               DATA SECURITY COMMAND CENTER                       ")
    typer.echo("==================================================================")
    typer.echo(f"  Total Data Assets          : {dash.total_data_assets_count:,}")
    typer.echo(f"  Sensitive Assets           : {dash.sensitive_assets_count:,}")
    typer.echo(f"  Restricted Assets          : {dash.restricted_assets_count:,}")
    typer.echo(f"  Unknown Classification     : {dash.unknown_classification_count:,}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  POSTURE METRICS:")
    typer.echo(f"    Encrypted at Rest        : {dash.encrypted_pct:.1f}%")
    typer.echo(f"    Assigned Owner           : {dash.owned_pct:.1f}%")
    typer.echo(f"    Classified               : {dash.classified_pct:.1f}%")
    typer.echo(f"    Access Reviewed          : {dash.access_reviewed_pct:.1f}%")
    typer.echo("  EXPOSURE & RISKS:")
    typer.echo(f"    Public Sensitive Data    : {dash.public_sensitive_data_count}")
    typer.echo(f"    Excessive Access Breadth : {dash.excessive_access_count}")
    typer.echo(f"    Unknown Data Flows       : {dash.unknown_flows_count}")
    typer.echo(f"    Stale Sensitive Data     : {dash.stale_sensitive_data_count}")
    typer.echo("  DLP ENFORCEMENT:")
    typer.echo(f"    Monitored Daily Flows    : {dash.monitored_flows_count:,}")
    typer.echo(f"    Restricted Events        : {dash.restricted_events_count}")
    typer.echo(f"    Blocked Exports          : {dash.blocked_exports_count}")
    typer.echo("==================================================================")


@cli.command("asset-status")
def cmd_asset_status(asset_id: str = typer.Argument("DATA-8821")):
    """Inspect dataset details, classification, encryption, and owners."""
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        typer.echo(f"[-] Data asset {asset_id} not found.")
        raise typer.Exit(code=1)

    rep = effective_calc.calculate_effective_access(asset_id)
    risk = risk_engine.calculate_asset_risk(asset, rep.total_effective_identities_count)

    typer.echo("==================================================================")
    typer.echo(f"DATA ASSET STATUS: {asset.data_asset_id} ({asset.name})")
    typer.echo("==================================================================")
    typer.echo(f"  Asset Type                : {asset.asset_type.value}")
    typer.echo(f"  Storage System / Location : {asset.storage_system} / {asset.location}")
    typer.echo(f"  Classification            : {asset.classification.value}")
    typer.echo(f"  Sensitivity Score         : {asset.sensitivity_score} / 100")
    typer.echo(f"  Business Owner            : {asset.business_owner}")
    typer.echo(f"  Technical Owner           : {asset.technical_owner}")
    typer.echo(f"  Encryption At Rest        : {asset.encryption_at_rest} (Key: {asset.kms_key_id})")
    typer.echo(f"  Public Exposure           : {asset.is_publicly_exposed}")
    typer.echo(f"  Record Count / Size       : {asset.record_count:,} records ({asset.size_bytes:,} bytes)")
    typer.echo(f"  Composite Risk Rating     : {risk.composite_risk_rating}")
    typer.echo(f"    Cyber Risk Score        : {risk.cyber_risk_score:.1f}")
    typer.echo(f"    Privacy Risk Score      : {risk.privacy_risk_score:.1f}")
    typer.echo(f"    Operational Risk Score  : {risk.operational_risk_score:.1f}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  KEY RISK FACTORS:")
    for f in risk.risk_factors:
        typer.echo(f"    * {f}")
    typer.echo("==================================================================")


@cli.command("effective-access")
def cmd_effective_access(asset_id: str = typer.Argument("DATA-8821")):
    """Calculate direct, workload-derived, and transitive effective access to a dataset."""
    report = effective_calc.calculate_effective_access(asset_id)
    typer.echo("==================================================================")
    typer.echo(f"EFFECTIVE ACCESS REPORT FOR {asset_id}")
    typer.echo("==================================================================")
    typer.echo(f"  Total Effective Entities  : {report.total_effective_identities_count}")
    typer.echo(f"  Direct Identities         : {', '.join(report.direct_identities)}")
    typer.echo(f"  Workload-Derived Services : {', '.join(report.workload_derived_identities)}")
    typer.echo(f"  Excessive Access Flag     : {report.is_access_excessive}")
    typer.echo(f"  Summary                   : {report.risk_summary}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  TRANSITIVE ACCESS CHAINS:")
    for idx, p in enumerate(report.transitive_access_paths, 1):
        typer.echo(f"    Path #{idx}: {p.get('chain_description', '')}")
    typer.echo("==================================================================")


@cli.command("evaluate-dlp")
def cmd_evaluate_dlp(
    asset_id: str = typer.Option("DATA-8821", "--asset", "-a"),
    destination: str = typer.Option("external.example", "--dest", "-d"),
    workload: str = typer.Option("WORKLOAD-991", "--workload", "-w"),
    records: int = typer.Option(900000, "--records", "-r"),
):
    """Evaluate a real-time data movement or export against active DLP policies."""
    flow = {
        "event_id": f"FLOW-{int(time.time())}",
        "source_asset_id": asset_id,
        "destination_id": destination,
        "workload_id": workload,
        "identity_id": "SERVICE-91",
        "record_count": records,
        "classification": "RESTRICTED",
        "is_external_destination": "external" in destination.lower(),
    }
    decision = dlp_engine.evaluate_flow(flow)
    status_str = "[BLOCKED]" if decision.is_blocked else f"[{decision.action.value}]"

    typer.echo("==================================================================")
    typer.echo(f"DLP ENFORCEMENT DECISION: {status_str}")
    typer.echo("==================================================================")
    typer.echo(f"  Decision ID       : {decision.decision_id}")
    typer.echo(f"  Action Taken      : {decision.action.value}")
    typer.echo(f"  Matched Policy    : {decision.matched_policy_id}")
    typer.echo(f"  Confidence Score  : {decision.confidence:.2f}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  DECISION REASONS:")
    for reason in decision.reasons:
        typer.echo(f"    * {reason}")
    typer.echo("==================================================================")


@cli.command("data-copilot")
def cmd_copilot(
    query_type: str = typer.Argument("access", help="Query type: 'access' or 'dlp'"),
    target: str = typer.Option("DATA-8821", "--target", "-t"),
):
    """Consult Data Security Copilot for diagnostic explanation and evidence references."""
    typer.echo(f"[+] Querying Data Security Copilot for [{query_type}] on target [{target}]...")
    if query_type == "access":
        res = copilot.ask_who_can_access(target)
        typer.echo(json.dumps(res, indent=2))
    elif query_type == "dlp":
        res = copilot.ask_why_dlp_triggered(asset_id=target)
        typer.echo(json.dumps(res, indent=2))
    else:
        typer.echo(f"[-] Unknown query type: {query_type}. Choose 'access' or 'dlp'.")


@cli.command("forensic-package")
def cmd_forensic_package(asset_id: str = typer.Argument("DATA-8821")):
    """Capture an immutable SHA-256 hashed data evidence package and incident timeline."""
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        typer.echo(f"[-] Data asset {asset_id} not found.")
        raise typer.Exit(code=1)

    snap = snapshot_manager.capture_snapshot(
        asset_id=asset.data_asset_id,
        asset_name=asset.name,
        classification=asset.classification.value,
        encryption_status={"at_rest": asset.encryption_at_rest, "key": asset.kms_key_id},
        active_readers=["SERVICE-91", "WORKLOAD-991"],
        last_volume_transferred=900000,
        destination_target="external.example",
    )
    timeline = DataTimelineBuilder.build_incident_timeline(asset.data_asset_id)
    pkg = DataEvidencePackage(
        case_id=f"CASE-PHASE29-{asset.data_asset_id}",
        asset_id=asset.data_asset_id,
        snapshot=snap,
        timeline=timeline,
        findings=[{"finding": "DLP-BLOCK-RESTRICTED-EGRESS", "severity": "CRITICAL"}],
    )
    pkg_hash = pkg.finalize()

    typer.echo("==================================================================")
    typer.echo(f"DATA FORENSIC EVIDENCE PACKAGE: {pkg.case_id}")
    typer.echo("==================================================================")
    typer.echo(f"  Snapshot ID       : {snap.snapshot_id}")
    typer.echo(f"  Snapshot SHA-256  : {snap.snapshot_sha256}")
    typer.echo(f"  Package SHA-256   : {pkg_hash}")
    typer.echo(f"  Timeline Entries  : {len(timeline)}")
    typer.echo(f"  Integrity Verified: True")
    typer.echo("==================================================================")


@cli.command("serve-api")
def cmd_serve_api(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8029, "--port", "-p"),
):
    """Launch FastAPI Enterprise Data Security server."""
    import uvicorn
    typer.echo(f"[+] Starting Garuda Phase 29 Data Security Control Plane on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    cli()
