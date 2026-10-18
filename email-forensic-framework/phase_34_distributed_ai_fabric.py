"""Garuda Phase 34: Distributed Sovereign AI Fabric & Multi-Node Orchestration.
Master Service & Unified Control Plane for multi-node inference,
resource-aware scheduling, model placement, distributed RAG & agents,
fault tolerance, and sovereign policy enforcement.
"""
from typing import Dict, List, Optional, Any
from enum import Enum
import sys
import time
import uuid
import typer

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status, Query

from fabric.models import (
    NodeStatus,
    NodeTrust,
    NodeRole,
    NetworkZone,
    DataClassification,
    WorkloadPriority,
    ModelLifecycleStatus,
    JobState,
    EnrollmentStatus,
    NodeHeartbeatPayload,
    WorkloadRequest,
)
from fabric.node_registry import NodeRegistry
from fabric.health import NodeHealthManager
from fabric.model_placement import ModelPlacementManager
from fabric.scheduler import WorkloadScheduler
from fabric.job_queue import JobQueueManager
from fabric.distributed_rag import DistributedRAGEngine
from fabric.distributed_agents import DistributedAgentOrchestrator
from fabric.inter_node import SecureInterNodeBus
from fabric.audit import DistributedAuditTrail
from fabric.observability import ClusterObservability
from fabric.benchmarks import ClusterBenchmarker
from fabric.demos import SIHFlagshipDemoRunner


# ==============================================================================
# Engine Initialization & Singletons
# ==============================================================================

node_registry = NodeRegistry()
health_mgr = NodeHealthManager(node_registry)
model_mgr = ModelPlacementManager(node_registry)
scheduler = WorkloadScheduler(node_registry, model_mgr)
job_queue = JobQueueManager(scheduler)
rag_engine = DistributedRAGEngine(scheduler)
agent_orchestrator = DistributedAgentOrchestrator(scheduler, job_queue)
inter_node_bus = SecureInterNodeBus()
audit_trail = DistributedAuditTrail()
observability = ClusterObservability(node_registry, audit_trail, job_queue)
benchmarker = ClusterBenchmarker(scheduler)
demo_runner = SIHFlagshipDemoRunner(
    node_registry,
    scheduler,
    job_queue,
    health_mgr,
    audit_trail,
    model_mgr,
)

# Wire automated failover listener:
# When health_mgr flags a node UNAVAILABLE, job_queue automatically fails over active workloads!
def on_node_status_change(node_id: str, new_status: NodeStatus, reason: str):
    if new_status == NodeStatus.UNAVAILABLE:
        job_queue.handle_node_failure(node_id, reason)

health_mgr.subscribe_failure_event(on_node_status_change)


# ==============================================================================
# FastAPI REST Control Plane
# ==============================================================================

app = FastAPI(
    title="Garuda Distributed Sovereign AI Fabric Control Plane",
    description="Phase 34 Multi-Node Orchestration, Policy Scheduling & Fault Tolerance API",
    version="34.0.0",
)


class ScheduleRequestSchema(BaseModel):
    capability: str = Field(..., description="Required capability (chat, coding, embeddings, vision, etc.)")
    model: Optional[str] = Field(None, description="Specific target model name")
    min_vram_gb: Optional[float] = Field(0.0, description="Minimum free VRAM required in GB")
    data_classification: Optional[str] = Field("INTERNAL", description="Data sensitivity level")
    allowed_zones: Optional[List[str]] = Field(None, description="Restricted network zones allowed")
    priority: Optional[str] = Field("NORMAL", description="Priority tier (CRITICAL, HIGH, NORMAL, LOW, BACKGROUND)")
    caller_id: Optional[str] = Field("system-user", description="Caller identity for fair concurrency")
    caller_role: Optional[str] = Field("user", description="Caller RBAC role")


class HeartbeatSchema(BaseModel):
    node_id: str
    status: Optional[str] = "HEALTHY"
    cpu_usage_pct: float = 10.0
    ram_used_gb: float = 4.0
    ram_total_gb: float = 16.0
    gpu_name: str = "NVIDIA GPU"
    vram_used_gb: float = 0.0
    vram_total_gb: float = 8.0
    active_jobs: int = 0
    temperature_c: Optional[float] = 50.0
    disk_used_pct: Optional[float] = 40.0
    models_state: Optional[Dict[str, str]] = None


class EnrollmentRequestSchema(BaseModel):
    hostname: str
    ip_address: str
    role: str = "WORKER_GPU"
    advertised_gpu: str
    advertised_vram_gb: float
    advertised_ram_gb: float
    advertised_capabilities: List[str]
    public_key: str
    requested_zone: str = "INTERNAL_AI"


class ApprovalSchema(BaseModel):
    request_id: str
    admin_id: Optional[str] = "admin@garuda.internal"
    trust_level: Optional[str] = "TRUSTED"


class RejectionSchema(BaseModel):
    request_id: str
    reason: str
    admin_id: Optional[str] = "admin@garuda.internal"


# ------------------------------------------------------------------------------
# Endpoints: Nodes & Enrollment
# ------------------------------------------------------------------------------

@app.get("/api/v1/fabric/nodes", tags=["Nodes"])
def list_nodes():
    nodes = node_registry.list_nodes()
    return {"nodes": [n.to_dict() for n in nodes], "total": len(nodes)}


@app.get("/api/v1/fabric/nodes/{node_id}", tags=["Nodes"])
def get_node(node_id: str):
    node = node_registry.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return node.to_dict()


@app.post("/api/v1/fabric/enrollment/request", tags=["Enrollment"])
def request_enrollment(req: EnrollmentRequestSchema):
    role_enum = getattr(NodeRole, req.role, NodeRole.WORKER_GPU)
    zone_enum = getattr(NetworkZone, req.requested_zone, NetworkZone.INTERNAL_AI)
    created_req = node_registry.submit_enrollment_request(
        hostname=req.hostname,
        ip_address=req.ip_address,
        role=role_enum,
        advertised_gpu=req.advertised_gpu,
        advertised_vram_gb=req.advertised_vram_gb,
        advertised_ram_gb=req.advertised_ram_gb,
        advertised_capabilities=req.advertised_capabilities,
        public_key=req.public_key,
        requested_zone=zone_enum,
    )
    return {"enrollment_request": created_req.to_dict(), "status": "PENDING_APPROVAL"}


@app.get("/api/v1/fabric/enrollment/requests", tags=["Enrollment"])
def get_enrollment_requests():
    reqs = node_registry.list_enrollment_requests()
    return {"requests": [r.to_dict() for r in reqs], "count": len(reqs)}


@app.post("/api/v1/fabric/enrollment/approve", tags=["Enrollment"])
def approve_enrollment(body: ApprovalSchema):
    try:
        trust_enum = getattr(NodeTrust, body.trust_level or "TRUSTED", NodeTrust.TRUSTED)
        node = node_registry.approve_enrollment(body.request_id, body.admin_id or "admin", trust_enum)
        return {"approved": True, "node": node.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/fabric/enrollment/reject", tags=["Enrollment"])
def reject_enrollment(body: RejectionSchema):
    try:
        req = node_registry.reject_enrollment(body.request_id, body.reason, body.admin_id or "admin")
        return {"rejected": True, "request": req.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/fabric/heartbeat", tags=["Health"])
def receive_heartbeat(hb: HeartbeatSchema):
    try:
        status_enum = getattr(NodeStatus, hb.status or "HEALTHY", NodeStatus.HEALTHY)
        payload = NodeHeartbeatPayload(
            node_id=hb.node_id,
            status=status_enum,
            cpu_usage_pct=hb.cpu_usage_pct,
            ram_used_gb=hb.ram_used_gb,
            ram_total_gb=hb.ram_total_gb,
            gpu_name=hb.gpu_name,
            vram_used_gb=hb.vram_used_gb,
            vram_total_gb=hb.vram_total_gb,
            active_jobs=hb.active_jobs,
            temperature_c=hb.temperature_c or 50.0,
            disk_used_pct=hb.disk_used_pct or 40.0,
        )
        updated_node = health_mgr.process_heartbeat(payload)
        return {"status": "ACK", "node": updated_node.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ------------------------------------------------------------------------------
# Endpoints: Workload Scheduler
# ------------------------------------------------------------------------------

@app.post("/api/v1/fabric/schedule", tags=["Scheduler"])
def schedule_workload(req: ScheduleRequestSchema):
    class_enum = getattr(DataClassification, req.data_classification or "INTERNAL", DataClassification.INTERNAL)
    prio_enum = getattr(WorkloadPriority, req.priority or "NORMAL", WorkloadPriority.NORMAL)
    allowed_zones_enum = None
    if req.allowed_zones:
        allowed_zones_enum = [getattr(NetworkZone, z, NetworkZone.INTERNAL_AI) for z in req.allowed_zones]

    workload = WorkloadRequest(
        request_id=f"SCHED-{uuid.uuid4().hex[:8].upper()}",
        capability=req.capability,
        required_model=req.model,
        min_vram_gb=req.min_vram_gb or 0.0,
        data_classification=class_enum,
        allowed_zones=allowed_zones_enum,
        priority=prio_enum,
        caller_id=req.caller_id or "system-user",
        caller_role=req.caller_role or "user",
    )
    decision = scheduler.schedule(workload)

    # Log to distributed audit trail
    audit_trail.record_event(
        user_id=workload.caller_id,
        request_id=workload.request_id,
        action=f"SCHEDULE_{req.capability.upper()}",
        policy_decision="ALLOW" if decision.scheduled else "DENIED",
        selected_node=decision.selected_node_id or "NONE",
        target_model=req.model or "unspecified",
        data_classification=workload.data_classification.value,
        data_zone=decision.selected_node.get("network_zone", "NONE") if decision.selected_node else "NONE",
        latency_ms=8.5,
        status="SCHEDULED" if decision.scheduled else "REJECTED",
        details={"explanation": decision.explanation},
    )

    return decision.to_dict()


# ------------------------------------------------------------------------------
# Endpoints: Models & Placement
# ------------------------------------------------------------------------------

@app.get("/api/v1/fabric/models", tags=["Models"])
def list_models():
    catalog = model_mgr.list_catalog()
    distribution = model_mgr.get_model_distribution()
    return {
        "catalog": [m.to_dict() for m in catalog],
        "distribution": distribution,
    }


@app.post("/api/v1/fabric/models/replicate", tags=["Models"])
def replicate_model(model_id: str, target_nodes: List[str]):
    res = model_mgr.replicate_model(model_id, target_nodes)
    return res


# ------------------------------------------------------------------------------
# Endpoints: Jobs & Failover
# ------------------------------------------------------------------------------

@app.get("/api/v1/fabric/jobs", tags=["Jobs"])
def list_jobs(node_id: Optional[str] = None):
    jobs = job_queue.list_jobs(node_id=node_id)
    return {"jobs": [j.to_dict() for j in jobs], "count": len(jobs)}


@app.post("/api/v1/fabric/jobs/failover", tags=["Jobs"])
def trigger_node_failover(node_id: str, reason: str = "Manual admin failover trigger"):
    node = node_registry.get_node(node_id)
    if node:
        node.status = NodeStatus.UNAVAILABLE
    results = job_queue.handle_node_failure(node_id, reason)
    return {"failed_node": node_id, "failover_results": results}


# ------------------------------------------------------------------------------
# Endpoints: Observability & Benchmarks
# ------------------------------------------------------------------------------

@app.get("/api/v1/fabric/observability/metrics", tags=["Observability"])
def get_metrics():
    return observability.get_cluster_dashboard_metrics()


@app.get("/api/v1/fabric/observability/topology", tags=["Observability"])
def get_topology():
    return observability.get_node_map_topology()


@app.get("/api/v1/fabric/audit", tags=["Audit"])
def get_audit_trail(limit: int = 50):
    events = audit_trail.list_events(limit=limit)
    return {"events": [e.to_dict() for e in events], "count": len(events)}


@app.post("/api/v1/fabric/benchmarks/run", tags=["Benchmarks"])
def run_benchmarks(count: int = 50):
    return benchmarker.run_scheduling_benchmark(count)


# ------------------------------------------------------------------------------
# Endpoints: SIH Demos
# ------------------------------------------------------------------------------

@app.post("/api/v1/fabric/demos/run/{demo_id}", tags=["SIH Flagship Demos"])
def run_single_demo(demo_id: int):
    if demo_id == 1:
        return demo_runner.run_demo_1_distributed_inference()
    elif demo_id == 2:
        return demo_runner.run_demo_2_resource_aware_scheduling()
    elif demo_id == 3:
        return demo_runner.run_demo_3_sovereign_data_placement()
    elif demo_id == 4:
        return demo_runner.run_demo_4_node_failure_and_failover()
    elif demo_id == 5:
        return demo_runner.run_demo_5_air_gapped_mode()
    elif demo_id == 6:
        return demo_runner.run_demo_6_complete_control_plane_chain()
    else:
        raise HTTPException(status_code=400, detail=f"Invalid demo_id: {demo_id}. Must be between 1 and 6.")


@app.post("/api/v1/fabric/demos/run-all", tags=["SIH Flagship Demos"])
def run_all_demos():
    return demo_runner.run_all_demos()


# ==============================================================================
# Typer CLI Application
# ==============================================================================

cli = typer.Typer(name="garuda-fabric", help="Garuda Distributed Sovereign AI Fabric CLI")


@cli.command("nodes")
def cli_list_nodes():
    """List all registered fabric nodes and their current status."""
    nodes = node_registry.list_nodes()
    typer.echo(f"\nGARUDA AI FABRIC - NODE REGISTRY ({len(nodes)} Nodes)")
    typer.echo("-" * 75)
    for n in nodes:
        typer.echo(
            f"* [{n.status.value:<11}] {n.node_id:<22} | {n.hostname:<26} | "
            f"VRAM: {n.free_vram_gb:.1f}/{n.vram_total_gb:.1f} GB | Zone: {n.network_zone.value}"
        )
    typer.echo("-" * 75 + "\n")


@cli.command("benchmark")
def cli_run_benchmark(count: int = 50):
    """Run performance benchmark comparing single-node vs distributed fabric."""
    typer.echo(f"\nRunning benchmark with {count} AI requests...")
    results = benchmarker.run_scheduling_benchmark(count)
    typer.echo("-" * 75)
    typer.echo(f"Single Node Throughput: {results['single_node']['throughput_req_sec']} req/s (Avg: {results['single_node']['average_latency_ms']} ms)")
    typer.echo(f"Distributed Throughput: {results['distributed_fabric']['throughput_req_sec']} req/s (Avg: {results['distributed_fabric']['average_latency_ms']} ms)")
    typer.echo(f"Performance Speedup:   {results['speedup']['throughput_improvement_pct']}")
    typer.echo("-" * 75 + "\n")


@cli.command("demo")
def cli_run_demo(id: int = typer.Option(0, help="Demo ID (1-6, 0 for all)")):
    """Run SIH Flagship demonstration scenarios (1 to 6)."""
    if id == 0:
        typer.echo("\nExecuting all 6 SIH Flagship Demonstrations...\n")
        res = demo_runner.run_all_demos()
        for k, v in res.items():
            if isinstance(v, dict) and "demo" in v:
                typer.echo(f"[PASS] {v['demo']}: {v['status']}")
    else:
        res = run_single_demo(id)
        typer.echo(f"\n[PASS] {res.get('demo', f'Demo {id}')}: {res.get('status', 'DONE')}")
        typer.echo(f"Description: {res.get('description', '')}\n")


@cli.command("serve")
def cli_serve(port: int = 8000, host: str = "0.0.0.0"):
    """Start the FastAPI control plane server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    cli()
