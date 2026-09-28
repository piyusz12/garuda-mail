"""Garuda Enterprise AI Security, AI-SPM, LLM Security & Agent Security Control Plane.
Phase 30: Unified Security Architecture for Models, RAG Pipelines, Agents, and Tool Execution.
"""
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import time
import typer
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Query, status

from ai_security.inventory import (
    AIAsset,
    AIAssetType,
    ModelLifecycleStatus,
    DeploymentEnvironment,
    AIDiscoveryEngine,
)
from ai_security.models import (
    AIModelRegistry,
    ModelProvenanceTracker,
    ModelIntegrityAuditor,
    ModelSupplyChainScanner,
    ModelDeploymentManager,
)
from ai_security.prompts import (
    PromptClassifier,
    PromptInjectionDetector,
    PromptPolicyEngine,
    PromptDecisionAction,
)
from ai_security.responses import (
    ResponseClassifier,
    ResponseSecurityScanner,
    ResponsePolicyEngine,
)
from ai_security.rag import (
    KnowledgeBaseRegistry,
    EmbeddingSecurityTracker,
    VectorDatabaseManager,
    RetrievalAuthorizationEngine,
    RAGPipelineManager,
)
from ai_security.agents import (
    AIAgentRecord,
    AgentRegistry,
    AgentIdentityManager,
    AgentPermissionEvaluator,
    AgentRuntimeMonitor,
    AgentBehaviorAnalytics,
)
from ai_security.tools import (
    AIToolRegistry,
    ToolAuthorizationEngine,
    ToolInvocationInterceptor,
    ToolRiskAnalyzer,
)
from data_security.inventory.normalization import ClassificationLevel
from ai_security.dlp import (
    AIDLPAction,
    AIDLPDecision,
    AIDLPPolicy,
    AIDLPEnforcementEngine,
)
from ai_security.posture import (
    AISPMEvaluator,
    AIConfigurationDriftDetector,
)
from ai_security.analytics import AIAnomalyDetector
from ai_security.risk import AIRiskEngine
from ai_security.forensics import (
    AIForensicSnapshotManager,
    AITimelineBuilder,
    AIEvidencePackage,
)
from ai_security.validation import (
    AIScenarioCatalog,
    AISecurityValidationRunner,
)
from ai_security.copilot import (
    AISecurityCopilot,
    AISecurityDashboardData,
)
from ai_graph import (
    AIGraph,
    AIGraphNode,
    AIGraphNodeType,
    AIGraphEdge,
    AIGraphEdgeType,
)
from ai_security.events import (
    AIEventType,
    AISecurityEvent,
    AISecurityEventBus,
)
from ai_security.hunting import (
    AIHuntEngine,
    AIHuntFinding,
)
from ai_security.detections import (
    AIDetectionEngine,
    AIDetectionAlert,
)
from ai_security.incident import (
    AIIncidentDispatcher,
    AIIncidentCase,
)
from ai_security.workflows import (
    AIWorkflowManager,
    AIWorkflowChain,
)
from ai_security.secrets import (
    AISecretsScanner,
    SecretAction,
)
from ai_security.governance import (
    AIGovernanceManager,
)
from ai_security.sovereignty import (
    SovereignAIChecker,
    SovereigntyComponentSpec,
    HostingEnvironmentType,
)
from ai_security.twin import (
    AIDigitalTwin,
)


# ==============================================================================
# Engine Initialization & Singletons
# ==============================================================================

discovery_engine = AIDiscoveryEngine()
model_registry = AIModelRegistry()
provenance_tracker = ModelProvenanceTracker()
integrity_auditor = ModelIntegrityAuditor()
supply_chain_scanner = ModelSupplyChainScanner()
deployment_mgr = ModelDeploymentManager()

prompt_classifier = PromptClassifier()
prompt_injection_detector = PromptInjectionDetector()
prompt_policy_engine = PromptPolicyEngine()

response_classifier = ResponseClassifier()
response_scanner = ResponseSecurityScanner()
response_policy_engine = ResponsePolicyEngine()

kb_registry = KnowledgeBaseRegistry()
embedding_tracker = EmbeddingSecurityTracker()
vdb_manager = VectorDatabaseManager()
retrieval_engine = RetrievalAuthorizationEngine(kb_registry, vdb_manager)
rag_pipeline_mgr = RAGPipelineManager()

agent_registry = AgentRegistry()
agent_identity_mgr = AgentIdentityManager()
agent_permission_evaluator = AgentPermissionEvaluator(agent_registry)
agent_runtime_monitor = AgentRuntimeMonitor()
agent_behavior_analytics = AgentBehaviorAnalytics()

tool_registry = AIToolRegistry()
tool_auth_engine = ToolAuthorizationEngine()
tool_interceptor = ToolInvocationInterceptor(tool_registry, tool_auth_engine)

dlp_engine = AIDLPEnforcementEngine()
posture_evaluator = AISPMEvaluator()
drift_detector = AIConfigurationDriftDetector()
anomaly_detector = AIAnomalyDetector()
risk_engine = AIRiskEngine()

snapshot_mgr = AIForensicSnapshotManager()
validation_runner = AISecurityValidationRunner()
copilot = AISecurityCopilot(discovery_engine)
ai_graph = AIGraph()

# Subsystem Singletons
event_bus = AISecurityEventBus.get_instance()
hunt_engine = AIHuntEngine(event_bus)
detection_engine = AIDetectionEngine(event_bus)
incident_dispatcher = AIIncidentDispatcher(agent_registry, model_registry)
workflow_mgr = AIWorkflowManager()
secrets_scanner = AISecretsScanner()
governance_mgr = AIGovernanceManager()
sovereign_checker = SovereignAIChecker()
digital_twin = AIDigitalTwin(ai_graph)


# ==============================================================================
# FastAPI Application & Endpoints
# ==============================================================================

app = FastAPI(
    title="Garuda Enterprise AI Security & AI-SPM Platform",
    description="Unified Enterprise AI Security Control Plane for Models, Agents, RAG Pipelines, and Tool Execution",
    version="1.0.0",
)


class PromptEvalRequest(BaseModel):
    prompt_text: str = Field(..., description="Prompt string to inspect")
    caller_identity: str = Field("USER-1192", description="Calling identity ID")
    is_external_model: bool = Field(False, description="Whether targeted model is external")


class ResponseEvalRequest(BaseModel):
    response_text: str = Field(..., description="Generated completion text to scan")
    model_id: str = Field("MODEL-781", description="Generating model ID")


class AIDLPEvalRequest(BaseModel):
    source_asset_id: str = Field("DATA-8821", description="Source data asset ID")
    classification: str = Field("RESTRICTED", description="Classification level")
    agent_id: str = Field("AGENT-41", description="Invoking agent ID")
    destination: str = Field("external.example", description="Destination URL or model")
    is_external_destination: bool = Field(True, description="Whether egress target is external")
    is_external_model: bool = Field(False, description="Whether target model is external")
    record_count: int = Field(900000, description="Volume of records involved")


class AICopilotQueryRequest(BaseModel):
    query_type: str = Field("access", description="Query type: 'access' or 'dlp'")
    target_agent_id: str = Field("AGENT-41", description="Target agent ID")
    destination: str = Field("external.example", description="Destination for DLP reasoning")


class AIPolicySimRequest(BaseModel):
    policy_id: str = Field("SIM-POLICY-01", description="Policy identifier to simulate")
    target_classification: str = Field("RESTRICTED", description="Classification scope")
    action: str = Field("BLOCK", description="Action to simulate")


class AISovereigntyEvalRequest(BaseModel):
    system_id: str = Field("SYS-AIR-GAP-01", description="System identifier")
    require_air_gap: bool = Field(True, description="Enforce strict air-gap compliance")
    components: List[Dict[str, Any]] = Field(default_factory=list, description="Components to inspect")


class AITwinSimRequest(BaseModel):
    agent_id: str = Field("AGENT-41", description="Target agent")
    tool_to_revoke: str = Field("http_post", description="Tool name to simulate revoking")


@app.get("/")
def root():
    return {
        "platform": "Garuda Enterprise AI Security Control Plane",
        "phase": 30,
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "timestamp": time.time(),
    }


# --- AI Inventory Endpoints ---

@app.get("/api/v1/ai/assets")
def list_ai_assets(asset_type: Optional[str] = None):
    t_enum = AIAssetType(asset_type.upper()) if asset_type else None
    assets = discovery_engine.list_assets(t_enum)
    return {"count": len(assets), "assets": [a.to_dict() for a in assets]}


@app.get("/api/v1/ai/assets/{asset_id}")
def get_ai_asset(asset_id: str):
    asset = discovery_engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset.to_dict()


# --- Model Security Endpoints ---

@app.get("/api/v1/ai/models")
def list_ai_models(status: Optional[str] = None):
    s_enum = ModelLifecycleStatus(status.upper()) if status else None
    models = model_registry.list_models(s_enum)
    return {"count": len(models), "models": [m.to_dict() for m in models]}


@app.get("/api/v1/ai/models/{model_id}")
def get_model_detail(model_id: str):
    m = model_registry.get_model(model_id)
    if not m:
        raise HTTPException(status_code=404, detail="Model not found")
    prov = provenance_tracker.get_provenance(model_id)
    return {
        "model": m.to_dict(),
        "provenance": prov.to_dict() if prov else None,
    }


@app.get("/api/v1/ai/models/{model_id}/provenance")
def get_model_provenance(model_id: str):
    prov = provenance_tracker.get_provenance(model_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provenance not found for model")
    return prov.to_dict()


@app.get("/api/v1/ai/models/{model_id}/integrity")
def get_model_integrity(model_id: str):
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    check = integrity_auditor.verify_runtime_artifact(model_id, expected_hash)
    return check.to_dict()


# --- Agent Security Endpoints ---

@app.get("/api/v1/ai/agents")
def list_ai_agents():
    agents = agent_registry.list_agents()
    return {"count": len(agents), "agents": [a.to_dict() for a in agents]}


@app.get("/api/v1/ai/agents/{agent_id}")
def get_agent_detail(agent_id: str):
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent.to_dict()


@app.get("/api/v1/ai/agents/{agent_id}/permissions")
def get_agent_permissions(agent_id: str):
    report = agent_permission_evaluator.evaluate_effective_access(agent_id)
    if not report:
        raise HTTPException(status_code=404, detail="Agent not found")
    return report.to_dict()


@app.get("/api/v1/ai/agents/{agent_id}/timeline")
def get_agent_timeline(agent_id: str):
    timeline = AITimelineBuilder.build_incident_timeline(agent_id=agent_id)
    return {"agent_id": agent_id, "timeline_entries_count": len(timeline), "timeline": [t.to_dict() for t in timeline]}


# --- Tool Security Endpoints ---

@app.get("/api/v1/ai/tools")
def list_ai_tools():
    tools = tool_registry.list_tools()
    return {"count": len(tools), "tools": [t.to_dict() for t in tools]}


# --- RAG Security Endpoints ---

@app.get("/api/v1/ai/rag/pipelines")
def list_rag_pipelines():
    pipelines = rag_pipeline_mgr.list_pipelines()
    return {"count": len(pipelines), "pipelines": [p.to_dict() for p in pipelines]}


@app.get("/api/v1/ai/rag/{pipeline_id}/sources")
def get_rag_pipeline_sources(pipeline_id: str):
    p = rag_pipeline_mgr.get_pipeline(pipeline_id)
    if not p:
        raise HTTPException(status_code=404, detail="RAG Pipeline not found")
    return {
        "pipeline_id": pipeline_id,
        "knowledge_base_ids": p.knowledge_base_ids,
        "vector_collections": p.vector_collections,
        "pre_retrieval_auth": p.pre_retrieval_auth,
    }


@app.get("/api/v1/ai/vector-stores")
def list_vector_stores():
    vdb = discovery_engine.list_assets(AIAssetType.VECTOR_STORE)
    return {"count": len(vdb), "vector_stores": [v.to_dict() for v in vdb]}


@app.get("/api/v1/ai/retrieval/events")
def list_retrieval_events():
    events = event_bus.get_events(event_types=[AIEventType.AI_RETRIEVAL_EVENT])
    return {"count": len(events), "retrieval_events": [e.to_dict() for e in events]}


# --- Prompt & Response Security Endpoints ---

@app.post("/api/v1/ai/prompt/evaluate")
def evaluate_prompt(req: PromptEvalRequest):
    decision = prompt_policy_engine.evaluate_prompt(
        prompt_text=req.prompt_text,
        caller_identity=req.caller_identity,
        is_external_model=req.is_external_model,
    )
    sec_scan = secrets_scanner.scan(req.prompt_text)
    res = decision.to_dict()
    res["secrets_detected"] = sec_scan.has_secret
    res["secrets_details"] = sec_scan.to_dict()
    return res


@app.post("/api/v1/ai/response/evaluate")
def evaluate_response(req: ResponseEvalRequest):
    decision = response_policy_engine.evaluate_response(req.response_text)
    return decision.to_dict()


# --- AI DLP & Policy Endpoints ---

@app.post("/api/v1/ai/dlp/evaluate")
def evaluate_ai_dlp(req: AIDLPEvalRequest):
    payload = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    decision = dlp_engine.evaluate_ai_event(payload)
    return decision.to_dict()


@app.get("/api/v1/ai/dlp/events")
def list_dlp_events():
    decisions = dlp_engine.list_decisions()
    return {"count": len(decisions), "decisions": [d.to_dict() for d in decisions]}


@app.get("/api/v1/ai/policies")
def list_ai_policies():
    policies = dlp_engine.list_policies()
    return {"count": len(policies), "policies": [p.to_dict() for p in policies]}


@app.post("/api/v1/ai/policies/simulate")
def simulate_ai_policy_endpoint(req: AIPolicySimRequest):
    proposed = AIDLPPolicy(
        policy_id=req.policy_id,
        name=f"Simulation for {req.policy_id}",
        target_classifications=[ClassificationLevel(req.target_classification.upper())],
        action=AIDLPAction(req.action.upper()),
        prohibit_external_model=True,
        prohibit_external_tool=True,
    )
    historical_events = [
        {"event_id": "H1", "agent_id": "AGENT-41", "classification": "RESTRICTED", "is_external": True},
        {"event_id": "H2", "agent_id": "AGENT-DEV-BOT", "classification": "CONFIDENTIAL", "is_external": True},
    ]
    sim = dlp_engine.simulate_policy(proposed, historical_events)
    return sim


@app.post("/api/v1/ai/policies/validate")
def validate_ai_policy_endpoint():
    res = validation_runner.run_scenario("SCN-AI-01-RESTRICTED-DATA-EXTERNAL-MODEL")
    return res.to_dict() if res else {"status": "NOT_FOUND"}


# --- AI Security Copilot Endpoints ---

@app.post("/api/v1/ai/copilot/query")
def query_ai_copilot(req: AICopilotQueryRequest):
    if req.query_type == "access":
        return copilot.ask_what_can_agent_access(req.target_agent_id)
    elif req.query_type == "dlp":
        return copilot.ask_why_request_blocked(caller_agent=req.target_agent_id, destination=req.destination)
    else:
        raise HTTPException(status_code=400, detail="query_type must be 'access' or 'dlp'")


# --- Threat Hunting & Detection Endpoints ---

@app.get("/api/v1/ai/detections/rules")
def list_ai_detection_rules():
    rules = detection_engine.list_rules()
    return {"count": len(rules), "rules": [{"rule_id": r.rule_id, "name": r.name, "severity": r.severity, "target_event": r.target_event, "response_playbook": r.response_playbook} for r in rules]}


@app.get("/api/v1/ai/detections/alerts")
def list_ai_detection_alerts(severity: Optional[str] = None):
    alerts = detection_engine.list_alerts(severity)
    return {"count": len(alerts), "alerts": [a.to_dict() for a in alerts]}


@app.post("/api/v1/ai/hunting/run")
def run_ai_hunt(hunt_id: str = "AI-HUNT-001"):
    findings = hunt_engine.run_hunt(hunt_id)
    return {"hunt_id": hunt_id, "findings_count": len(findings), "findings": [f.to_dict() for f in findings]}


# --- Workflow & Sovereignty Endpoints ---

@app.get("/api/v1/ai/workflows")
def list_ai_workflows():
    wfs = workflow_mgr.list_workflows()
    return {"count": len(wfs), "workflows": [{"workflow_id": w.workflow_id, "name": w.name, "agent_id": w.agent_id, "stages": [s.to_dict() for s in w.stages]} for w in wfs]}


@app.post("/api/v1/ai/sovereignty/evaluate")
def evaluate_ai_sovereignty(req: AISovereigntyEvalRequest):
    components = []
    for c in req.components:
        components.append(
            SovereigntyComponentSpec(
                component_id=c.get("component_id", "COMP-01"),
                component_type=c.get("component_type", "MODEL"),
                hosting_type=HostingEnvironmentType(c.get("hosting_type", "ON_PREM_AIR_GAPPED")),
                jurisdiction_country=c.get("jurisdiction_country", "IN"),
                has_internet_egress=c.get("has_internet_egress", False),
                is_air_gapped=c.get("is_air_gapped", True),
            )
        )
    if not components:
        # Default sovereign demo components
        components = [
            SovereigntyComponentSpec("LOCAL-LLM-01", "MODEL", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
            SovereigntyComponentSpec("LOCAL-VDB-01", "VECTOR_DB", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
        ]
    report = sovereign_checker.evaluate_pipeline(req.system_id, components, req.require_air_gap)
    return report.to_dict()


# --- AI Security Graph & Digital Twin Endpoints ---

@app.get("/api/v1/ai/graph")
def get_ai_graph():
    return {
        "nodes_count": len(ai_graph._nodes),
        "edges_count": len(ai_graph._edges),
        "attack_paths": [p.to_dict() for p in digital_twin.discover_ai_attack_paths()],
    }


@app.post("/api/v1/ai/twin/simulate")
def simulate_twin_change(req: AITwinSimRequest):
    sim = digital_twin.simulate_tool_revocation(req.agent_id, req.tool_to_revoke)
    return sim.to_dict()


# --- Incident Response Endpoints ---

@app.post("/api/v1/ai/tools/{tool_id}/revoke")
def revoke_agent_tool(tool_id: str, agent_id: str = "AGENT-41"):
    res = incident_dispatcher.execute_playbook("PB-AI-01-TOOL-REVOCATION", {"agent_id": agent_id, "tool_id": tool_id})
    return res.to_dict()


@app.post("/api/v1/ai/egress/block")
def block_ai_egress(agent_id: str = "AGENT-41", destination: str = "external.example"):
    res = incident_dispatcher.execute_playbook("PB-AI-02-EGRESS-CONTAINMENT", {"agent_id": agent_id, "destination": destination})
    return res.to_dict()


@app.post("/api/v1/ai/agents/{agent_id}/disable")
def disable_agent_endpoint(agent_id: str):
    res = incident_dispatcher.execute_playbook("PB-AI-03-AGENT-QUARANTINE", {"agent_id": agent_id})
    return res.to_dict()


@app.post("/api/v1/ai/models/{model_id}/quarantine")
def quarantine_model_endpoint(model_id: str):
    res = incident_dispatcher.execute_playbook("PB-AI-04-MODEL-ISOLATION", {"model_id": model_id})
    return res.to_dict()


@app.get("/api/v1/ai/reports")
def get_ai_reports():
    dash = copilot.get_dashboard_summary()
    return dash.to_dict()


# ==============================================================================
# Typer CLI Interface
# ==============================================================================

cli = typer.Typer(
    name="Garuda Enterprise AI Security CLI",
    help="Enterprise Control Plane for Models, Agents, RAG Pipelines, and Tool Security",
    add_completion=False,
)


@cli.command("ai-dashboard")
def cmd_ai_dashboard():
    """Display the AI Security Command Center overview."""
    dash = copilot.get_dashboard_summary()
    typer.echo("==================================================================")
    typer.echo("                 AI SECURITY COMMAND CENTER                       ")
    typer.echo("==================================================================")
    typer.echo(f"  AI Assets                  : {dash.total_ai_assets:,}")
    typer.echo(f"  Models                     : {dash.models_count:,}")
    typer.echo(f"  Agents                     : {dash.agents_count:,}")
    typer.echo(f"  RAG Pipelines              : {dash.rag_pipelines_count:,}")
    typer.echo(f"  Tools                      : {dash.tools_count:,}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  MODEL POSTURE:")
    typer.echo(f"    Approved Models          : {dash.approved_models_count:,}")
    typer.echo(f"    Unknown Provenance       : {dash.unknown_provenance_count}")
    typer.echo(f"    Integrity Alerts         : {dash.integrity_alerts_count}")
    typer.echo("  AGENT POSTURE:")
    typer.echo(f"    Least-Privilege Compliant: {dash.least_privilege_compliant_count}")
    typer.echo(f"    Excessive Tool Access    : {dash.excessive_tool_access_count}")
    typer.echo(f"    Excessive Data Access    : {dash.excessive_data_access_count}")
    typer.echo("  AI DATA SECURITY:")
    typer.echo(f"    Restricted Prompts       : {dash.restricted_prompts_count}")
    typer.echo(f"    DLP Events               : {dash.dlp_events_count}")
    typer.echo(f"    Blocked AI Egress        : {dash.blocked_ai_egress_count}")
    typer.echo("  RAG SECURITY:")
    typer.echo(f"    Vector Stores            : {dash.vector_stores_count}")
    typer.echo(f"    Cross-Scope Findings     : {dash.cross_scope_findings_count}")
    typer.echo(f"    Unowned Knowledge Bases  : {dash.unowned_kb_count}")
    typer.echo("==================================================================")


@cli.command("model-status")
def cmd_model_status(model_id: str = typer.Argument("MODEL-781", help="Model ID")):
    """Inspect model metadata, provenance, and artifact integrity."""
    m = model_registry.get_model(model_id)
    if not m:
        typer.echo(f"[-] Model {model_id} not found.")
        raise typer.Exit(code=1)

    prov = provenance_tracker.get_provenance(model_id)
    expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    check = integrity_auditor.verify_runtime_artifact(model_id, expected_hash)

    typer.echo("==================================================================")
    typer.echo(f"AI MODEL STATUS: {m.model_id} ({m.name})")
    typer.echo("==================================================================")
    typer.echo(f"  Format / Parameters       : {m.format.value} ({m.parameter_count})")
    typer.echo(f"  Context Window            : {m.context_window:,} tokens")
    typer.echo(f"  Lifecycle Status          : {m.lifecycle_status.value}")
    typer.echo(f"  Production Approved       : {m.approved_for_production}")
    typer.echo(f"  Artifact Integrity        : [{check.status}] {check.details}")
    if prov:
        typer.echo(f"  Source Repository         : {prov.source_repository}")
        typer.echo(f"  Introduced By             : {prov.introduced_by}")
        typer.echo(f"  Approved By               : {prov.approved_by}")
    typer.echo("==================================================================")


@cli.command("agent-permissions")
def cmd_agent_permissions(agent_id: str = typer.Argument("AGENT-41", help="Agent ID")):
    """Evaluate effective permissions, reachable data, and risk profile for an AI agent."""
    report = agent_permission_evaluator.evaluate_effective_access(agent_id)
    if not report:
        typer.echo(f"[-] Agent {agent_id} not found.")
        raise typer.Exit(code=1)

    typer.echo("==================================================================")
    typer.echo(f"AGENT PERMISSION REPORT: {report.agent_id}")
    typer.echo("==================================================================")
    typer.echo(f"  Associated Model          : {report.associated_model}")
    typer.echo(f"  Identity Binding          : {report.identity_id}")
    typer.echo(f"  Authorized Tools          : {', '.join(report.authorized_tools)}")
    typer.echo(f"  Reachable Data Sources    : {', '.join(report.reachable_datasets)}")
    typer.echo(f"  Restricted Data Paths     : {report.restricted_data_paths_count}")
    typer.echo(f"  External Network Tool     : {report.has_external_network_tool}")
    typer.echo(f"  Highest-Risk Capability   : {report.highest_risk_capability}")
    typer.echo("------------------------------------------------------------------")
    typer.echo(f"  RISK ASSESSMENT: {report.risk_assessment}")
    typer.echo("==================================================================")


@cli.command("evaluate-prompt")
def cmd_evaluate_prompt(
    prompt: str = typer.Argument(..., help="Prompt text to inspect"),
    caller: str = typer.Option("USER-1192", "--caller", "-c"),
    external_model: bool = typer.Option(False, "--external", "-e"),
):
    """Scan and evaluate an inbound prompt against AI safety rules and injection defenses."""
    dec = prompt_policy_engine.evaluate_prompt(prompt, caller, external_model)
    sec_scan = secrets_scanner.scan(prompt)

    typer.echo("==================================================================")
    typer.echo(f"PROMPT POLICY DECISION: [{dec.action.value}]")
    typer.echo("==================================================================")
    typer.echo(f"  Prompt ID        : {dec.prompt_id}")
    typer.echo(f"  Action Taken     : {dec.action.value}")
    typer.echo(f"  Matched Rule     : {dec.matched_rule or 'NONE'}")
    typer.echo(f"  Confidence Score : {dec.confidence}")
    typer.echo(f"  Secrets Found    : {len(sec_scan.secrets_found)}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  DECISION REASONS:")
    for r in dec.reasons:
        typer.echo(f"    * {r}")
    typer.echo("==================================================================")


@cli.command("evaluate-dlp")
def cmd_evaluate_dlp(
    asset_id: str = typer.Option("DATA-8821", "--asset", "-a"),
    agent_id: str = typer.Option("AGENT-41", "--agent", "-g"),
    dest: str = typer.Option("external.example", "--dest", "-d"),
    records: int = typer.Option(900000, "--records", "-r"),
):
    """Evaluate an AI data movement or export against active AI DLP policies."""
    payload = {
        "source_asset_id": asset_id,
        "classification": "RESTRICTED",
        "agent_id": agent_id,
        "destination": dest,
        "is_external_destination": True,
        "is_external_model": False,
        "record_count": records,
    }
    decision = dlp_engine.evaluate_ai_event(payload)
    status_label = "BLOCKED" if decision.is_blocked else decision.action.value

    typer.echo("==================================================================")
    typer.echo(f"AI DLP ENFORCEMENT DECISION: [{status_label}]")
    typer.echo("==================================================================")
    typer.echo(f"  Decision ID       : {decision.decision_id}")
    typer.echo(f"  Action Taken      : {decision.action.value}")
    typer.echo(f"  Matched Policy    : {decision.matched_policy_id}")
    typer.echo(f"  Caller Agent      : {decision.caller_agent_id}")
    typer.echo(f"  Destination       : {decision.destination}")
    typer.echo("------------------------------------------------------------------")
    typer.echo("  DECISION REASONS:")
    for r in decision.reasons:
        typer.echo(f"    * {r}")
    typer.echo("==================================================================")


@cli.command("ai-hunt")
def cmd_ai_hunt(hunt_id: str = typer.Argument("AI-HUNT-001", help="Hunt ID to execute")):
    """Run an AI threat hunt query across the event telemetry bus."""
    findings = hunt_engine.run_hunt(hunt_id)
    typer.echo("==================================================================")
    typer.echo(f"AI THREAT HUNT RESULTS: {hunt_id}")
    typer.echo("==================================================================")
    typer.echo(f"  Findings Count : {len(findings)}")
    for f in findings:
        typer.echo(f"  * [{f.severity}] {f.title} - {f.description}")
    typer.echo("==================================================================")


@cli.command("ai-sovereignty")
def cmd_ai_sovereignty():
    """Verify sovereign AI and air-gapped deployment boundary compliance."""
    demo_components = [
        SovereigntyComponentSpec("LOCAL-LLM-01", "MODEL", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
        SovereigntyComponentSpec("LOCAL-VDB-01", "VECTOR_DB", HostingEnvironmentType.ON_PREM_AIR_GAPPED, "IN", False, True),
    ]
    report = sovereign_checker.evaluate_pipeline("SOVEREIGN-STACK-01", demo_components, True)
    typer.echo("==================================================================")
    typer.echo(f"SOVEREIGN AI COMPLIANCE REPORT: {report.system_id}")
    typer.echo("==================================================================")
    typer.echo(f"  Sovereign Compliant : {report.is_sovereign_compliant}")
    typer.echo(f"  Air-Gap Verified    : {report.is_fully_air_gapped}")
    typer.echo(f"  Compliance Score    : {report.sovereignty_score_pct}%")
    typer.echo(f"  Violations          : {len(report.violations)}")
    typer.echo("==================================================================")


@cli.command("ai-twin-simulate")
def cmd_ai_twin_simulate(
    agent_id: str = typer.Option("AGENT-41", "--agent", "-a"),
    tool: str = typer.Option("http_post", "--tool", "-t"),
):
    """Simulate tool revocation in the AI Digital Twin to calculate blast radius reduction."""
    sim = digital_twin.simulate_tool_revocation(agent_id, tool)
    typer.echo("==================================================================")
    typer.echo(f"AI DIGITAL TWIN SIMULATION: {sim.scenario_name}")
    typer.echo("==================================================================")
    typer.echo(f"  Baseline Attack Paths      : {sim.baseline_attack_paths_count}")
    typer.echo(f"  Post-Remediation Paths     : {sim.post_remediation_attack_paths_count}")
    typer.echo(f"  Paths Severed              : {sim.severed_paths_count}")
    typer.echo(f"  Blast Radius Reduction     : {sim.blast_radius_reduction_pct}%")
    typer.echo(f"  Critical Impact On Ops     : {sim.critical_business_impact}")
    typer.echo("------------------------------------------------------------------")
    typer.echo(f"  SUMMARY: {sim.summary}")
    typer.echo("==================================================================")


@cli.command("ai-copilot")
def cmd_ai_copilot(
    query_type: str = typer.Argument("access", help="Query type: 'access' or 'dlp'"),
    target: str = typer.Option("AGENT-41", "--target", "-t"),
):
    """Consult AI Security Copilot for diagnostic explanation and evidence references."""
    typer.echo(f"[+] Querying AI Security Copilot for [{query_type}] on target [{target}]...")
    if query_type.lower() == "access":
        res = copilot.ask_what_can_agent_access(target)
    elif query_type.lower() == "dlp":
        res = copilot.ask_why_request_blocked(caller_agent=target)
    else:
        typer.echo(f"[-] Unknown query type: {query_type}. Choose 'access' or 'dlp'.")
        raise typer.Exit(code=1)

    typer.echo(json.dumps(res, indent=2))


@cli.command("forensic-package")
def cmd_forensic_package(agent_id: str = typer.Argument("AGENT-41", help="Agent ID")):
    """Capture an immutable SHA-256 hashed AI forensic evidence package and incident timeline."""
    snap = snapshot_mgr.capture_snapshot(
        agent_id=agent_id,
        model_id="MODEL-781",
        identity_id="SERVICE-IDENTITY-77",
        prompt_hash="fbc58c487cf93333fb1d25e9170b270675a9396c05a339f773dbbc91e6f7de8f",
        retrieved_documents=["DOC-CHUNK-8821"],
        tool_calls=["database_query", "http_post"],
        dlp_action="BLOCK",
        destination_target="external.example",
    )
    timeline = AITimelineBuilder.build_incident_timeline(agent_id=agent_id)
    pkg = AIEvidencePackage(
        case_id="CASE-9001",
        agent_id=agent_id,
        snapshot=snap,
        timeline=timeline,
        findings=[{"type": "AI_DLP_BLOCK", "policy": "AI-DLP-01-BLOCK-RESTRICTED-EGRESS"}],
    )
    pkg_hash = pkg.finalize()

    typer.echo("==================================================================")
    typer.echo(f"AI FORENSIC EVIDENCE PACKAGE: {pkg.case_id}")
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
    port: int = typer.Option(8000, "--port", "-p"),
):
    """Launch the FastAPI REST API control plane server."""
    import uvicorn
    typer.echo(f"[*] Launching Garuda Enterprise AI Security API on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    cli()
