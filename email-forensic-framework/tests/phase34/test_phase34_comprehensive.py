"""Master Test Suite for Phase 34: Distributed Sovereign AI Fabric & Multi-Node Orchestration.
Validates all 26 modules, node identity, secure enrollment, capability discovery,
resource-aware & data-locality scheduling, model placement & replication,
distributed RAG, distributed agents with checkpointing, secure inter-node bus,
automatic failover, cluster observability, security test cases, all 6 SIH Flagship Demos,
and REST control-plane APIs.
"""
import pytest
import time
from starlette.testclient import TestClient

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
    WorkloadRequest,
    NodeHeartbeatPayload,
)
from fabric.node_registry import NodeRegistry
from fabric.health import NodeHealthManager
from fabric.model_placement import ModelPlacementManager, FabricModelSpec
from fabric.scheduler import WorkloadScheduler
from fabric.job_queue import JobQueueManager
from fabric.distributed_rag import DistributedRAGEngine
from fabric.distributed_agents import DistributedAgentOrchestrator
from fabric.inter_node import SecureInterNodeBus
from fabric.audit import DistributedAuditTrail
from fabric.observability import ClusterObservability
from fabric.benchmarks import ClusterBenchmarker
from fabric.demos import SIHFlagshipDemoRunner
from phase_34_distributed_ai_fabric import app


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# Test 1: Node Registry, Cryptographic Identity & Default Topology (34.2, 34.3)
# ------------------------------------------------------------------------------
def test_node_registry_and_identity():
    reg = NodeRegistry()
    nodes = reg.list_nodes()
    assert len(nodes) >= 3

    node1 = reg.get_node("NODE-001")
    assert node1 is not None
    assert node1.role == NodeRole.WORKER_GPU
    assert node1.gpu_name == "NVIDIA GeForce RTX 4060 Laptop GPU"
    assert node1.vram_total_gb == 8.0
    assert node1.free_vram_gb == 4.8
    assert "chat" in node1.capabilities
    assert "coding" in node1.capabilities

    # Verify cryptographic identity
    ident = reg.generate_node_identity("TEST-NODE-99")
    assert ident.node_id == "TEST-NODE-99"
    assert ident.fingerprint.startswith("SHA256:")
    assert reg.verify_node_identity("TEST-NODE-99", ident.public_key) is True
    assert reg.verify_node_identity("TEST-NODE-99", "INVALID-KEY") is False


# ------------------------------------------------------------------------------
# Test 2: Secure Node Enrollment Workflow (34.4)
# ------------------------------------------------------------------------------
def test_secure_node_enrollment():
    reg = NodeRegistry()
    # 1. New worker submits enrollment
    req = reg.submit_enrollment_request(
        hostname="lab-gpu-node-05",
        ip_address="192.168.1.105",
        role=NodeRole.WORKER_GPU,
        advertised_gpu="RTX 4090",
        advertised_vram_gb=24.0,
        advertised_ram_gb=64.0,
        advertised_capabilities=["vision", "vllm", "embeddings"],
        public_key="PUBKEY-NODE-05-SECURE",
        requested_zone=NetworkZone.INTERNAL_AI,
    )
    assert req.status == EnrollmentStatus.PENDING_APPROVAL
    assert req.request_id.startswith("ENROLL-")

    # 2. Administrator reviews and approves
    approved_node = reg.approve_enrollment(req.request_id, admin_id="security-lead@garuda.internal")
    assert approved_node is not None
    assert approved_node.status == NodeStatus.HEALTHY
    assert approved_node.trust_level == NodeTrust.TRUSTED
    assert reg.get_node(approved_node.node_id) is not None

    # 3. Test rejection flow
    req2 = reg.submit_enrollment_request(
        hostname="untrusted-node",
        ip_address="192.168.1.251",
        role=NodeRole.WORKER_GPU,
        advertised_gpu="Unknown",
        advertised_vram_gb=4.0,
        advertised_ram_gb=8.0,
        advertised_capabilities=["chat"],
        public_key="ROGUE-KEY",
    )
    rejected_req = reg.reject_enrollment(req2.request_id, reason="Unverified hardware vendor")
    assert rejected_req.status == EnrollmentStatus.REJECTED


# ------------------------------------------------------------------------------
# Test 3: Capability Discovery Matrix (34.6)
# ------------------------------------------------------------------------------
def test_capability_discovery():
    reg = NodeRegistry()
    matrix = reg.get_capabilities_matrix()
    assert "chat" in matrix
    assert "NODE-001" in matrix["chat"]
    assert "vision" in matrix
    assert "NODE-002" in matrix["vision"]
    assert "vector_store" in matrix
    assert "NODE-003" in matrix["vector_store"]


# ------------------------------------------------------------------------------
# Test 4: Node Health Manager, Heartbeat & Failure Detection (34.5, 34.16)
# ------------------------------------------------------------------------------
def test_health_manager_and_failure_detection():
    reg = NodeRegistry()
    health = NodeHealthManager(reg, degraded_threshold_sec=5.0, unavailable_threshold_sec=10.0)

    # 1. Valid heartbeat updates vitals
    hb = NodeHeartbeatPayload(
        node_id="NODE-001",
        status=NodeStatus.HEALTHY,
        cpu_usage_pct=45.0,
        ram_used_gb=10.0,
        ram_total_gb=16.0,
        gpu_name="RTX 4060",
        vram_used_gb=4.0,
        vram_total_gb=8.0,
        active_jobs=2,
        temperature_c=56.0,
        disk_used_pct=40.0,
    )
    updated = health.process_heartbeat(hb)
    assert updated.cpu_usage_pct == 45.0
    assert updated.active_jobs == 2

    # 2. VRAM Saturation / OOM Detection
    hb_oom = NodeHeartbeatPayload(
        node_id="NODE-001",
        status=NodeStatus.HEALTHY,
        cpu_usage_pct=95.0,
        ram_used_gb=15.0,
        ram_total_gb=16.0,
        gpu_name="RTX 4060",
        vram_used_gb=8.0,
        vram_total_gb=8.0,
        active_jobs=5,
    )
    oom_node = health.process_heartbeat(hb_oom)
    assert oom_node.status == NodeStatus.DEGRADED
    assert "GPU VRAM Saturation" in oom_node.security_state

    # 3. Heartbeat Expiration Scanner
    node1 = reg.get_node("NODE-001")
    node1.last_seen = time.time() - 15.0  # Simulate 15s elapsed
    events = health.scan_for_failures()
    assert len(events) >= 1
    assert any(e["node_id"] == "NODE-001" and e["new_status"] == NodeStatus.UNAVAILABLE.value for e in events)


# ------------------------------------------------------------------------------
# Test 5: Workload Scheduler & Explainable Decisions (34.7, 34.8, 34.48, 34.49)
# ------------------------------------------------------------------------------
def test_workload_scheduler():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)

    # Standard chat request
    req = WorkloadRequest(
        request_id="REQ-TEST-01",
        capability="chat",
        required_model="qwen-local",
        caller_id="analyst",
    )
    decision = sched.schedule(req)
    assert decision.scheduled is True
    assert decision.selected_node_id in ("NODE-001", "NODE-002")
    assert "Selected" in decision.explanation
    assert len(decision.candidate_scores) >= 3

    # Vision request -> Must route to Node 2 (Node 1 has no vision)
    vision_req = WorkloadRequest(
        request_id="REQ-VISION-01",
        capability="vision",
        required_model="qwen-vl-vision",
        min_vram_gb=7.0,
        caller_id="analyst",
    )
    vision_dec = sched.schedule(vision_req)
    assert vision_dec.scheduled is True
    assert vision_dec.selected_node_id == "NODE-002"
    assert "Lacks required capability 'vision'" in vision_dec.rejected_reasons.get("NODE-001", "")


# ------------------------------------------------------------------------------
# Test 6: Model Placement & Model Replication (34.9, 34.10)
# ------------------------------------------------------------------------------
def test_model_placement_and_replication():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)

    # Replicate qwen-coder-7b to NODE-001 (has 4.8 GB free, model needs 6.5 GB -> Insufficient)
    can_place, reason = model_mgr.can_place_model("qwen-coder-7b", reg.get_node("NODE-001"))
    assert can_place is False
    assert "Insufficient VRAM" in reason

    # Place lightweight model qwen-local (needs 2.2 GB) -> Should succeed
    can_place_light, _ = model_mgr.can_place_model("qwen-local", reg.get_node("NODE-001"))
    assert can_place_light is True

    # Replicate model to NODE-002
    res = model_mgr.replicate_model("qwen-local", ["NODE-002"])
    assert res["success"] is True


# ------------------------------------------------------------------------------
# Test 7: Data Locality & Sovereign Policy Enforcement (34.11, 34.30)
# ------------------------------------------------------------------------------
def test_data_locality_enforcement():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)

    # RESTRICTED classification requires RESTRICTED_AI zone (NODE-001)
    req = WorkloadRequest(
        request_id="REQ-RESTRICTED-01",
        capability="embeddings",
        data_classification=DataClassification.RESTRICTED,
        caller_id="officer",
    )
    dec = sched.schedule(req)
    assert dec.scheduled is True
    assert dec.selected_node_id == "NODE-001"
    # Node 2 is in INTERNAL_AI, Node 3 is in STORAGE_NET -> Both rejected for RESTRICTED
    assert "Data locality violation" in dec.rejected_reasons.get("NODE-002", "")
    assert "Data locality violation" in dec.rejected_reasons.get("NODE-003", "")


# ------------------------------------------------------------------------------
# Test 8: Distributed RAG Ingestion & Querying (34.12, 34.19)
# ------------------------------------------------------------------------------
def test_distributed_rag_pipeline():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    rag = DistributedRAGEngine(sched)

    # 1. Distributed ingestion batch partitioning (10,000 documents)
    ingestion = rag.partition_ingestion_workload(
        collection_id="MAIL-FORENSIC-CORPUS",
        total_documents=2500,
        batch_size=500,
    )
    assert ingestion["total_batches"] == 5
    assert len(ingestion["batches"]) == 5
    assert ingestion["batches"][0]["document_count"] == 500

    # 2. Distributed RAG Query execution
    res = rag.execute_distributed_rag_query(
        query="Verify STARTTLS negotiation on port 587",
        collection_id="MAIL-FORENSIC-CORPUS",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    assert res["sovereignty_preserved"] is True
    assert len(res["retrieved_chunks"]) == 5
    assert "pipeline" in res
    assert res["pipeline"]["retrieval_node"] is not None


# ------------------------------------------------------------------------------
# Test 9: Distributed Agents with Checkpoint Migration (34.13, 34.21)
# ------------------------------------------------------------------------------
def test_distributed_agent_checkpointing():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    queue = JobQueueManager(sched)
    agent_orch = DistributedAgentOrchestrator(sched, queue)

    # Dispatch agent
    run = agent_orch.dispatch_agent_task(
        agent_id="AGENT-FORENSIC-01",
        task_prompt="Inspect email capture and calculate CBOM score",
        required_tools=["pcap_analyzer", "cbom_generator"],
    )
    assert run["status"] == "RUNNING"
    assert len(run["plan"]) == 4

    # Step 1
    step1 = agent_orch.execute_agent_step(run["run_id"])
    assert step1["status"] == "SUCCESS"
    assert step1["step_number"] == 1

    # Step 2
    step2 = agent_orch.execute_agent_step(run["run_id"])
    assert step2["step_number"] == 2

    # Checkpoint is persisted in durable job queue
    job = queue.get_job(run["job_id"])
    assert job is not None
    assert len(job.checkpoints) == 2

    # Migrate task to new node
    mig = agent_orch.migrate_agent_task(run["run_id"], "NODE-001")
    assert mig["checkpoint_restored"] is True
    assert mig["resumed_from_step"] == 2


# ------------------------------------------------------------------------------
# Test 10: Secure Inter-Node Envelopes & Network Segmentation (34.14, 34.15)
# ------------------------------------------------------------------------------
def test_secure_inter_node_bus():
    bus = SecureInterNodeBus()

    # 1. Create and verify valid envelope
    env = bus.create_envelope(
        request_id="REQ-INT-01",
        source_node_id="GARUDA-CONTROL-PLANE",
        target_node_id="NODE-001",
        network_zone=NetworkZone.MANAGEMENT_NET,
        job_id="JOB-101",
        payload={"task": "INFERENCE", "model": "qwen-local"},
    )
    valid, msg = bus.verify_envelope(env)
    assert valid is True

    # 2. Replay attack rejection
    replay_valid, replay_msg = bus.verify_envelope(env)
    assert replay_valid is False
    assert "Replay attack detected" in replay_msg

    # 3. Network segmentation rules (Section 34.15)
    seg1, _ = bus.validate_network_segmentation(NetworkZone.MANAGEMENT_NET, NetworkZone.RESTRICTED_AI)
    assert seg1 is True

    # Direct transfer from RESTRICTED_AI to GENERAL_AI without control plane mediator is blocked
    seg2, seg2_msg = bus.validate_network_segmentation(NetworkZone.RESTRICTED_AI, NetworkZone.GENERAL_AI)
    assert seg2 is False
    assert "Cross-zone violation" in seg2_msg


# ------------------------------------------------------------------------------
# Test 11: Automated Failover & Job Persistence (34.17, 34.18)
# ------------------------------------------------------------------------------
def test_job_persistence_and_failover():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    queue = JobQueueManager(sched)

    # 1. Create job on Node 2
    job = queue.create_job(
        capability="llm_inference",
        assigned_node_id="NODE-002",
        priority=WorkloadPriority.HIGH,
    )
    queue.checkpoint_job(job.job_id, "Step 1: Ingesting PCAP", {"bytes": 4096})

    # 2. Node 2 crashes
    node2 = reg.get_node("NODE-002")
    node2.status = NodeStatus.UNAVAILABLE

    # 3. Automated failover triggers
    failovers = queue.handle_node_failure("NODE-002", reason="OOM Crash Simulation")
    assert len(failovers) >= 1
    assert failovers[0]["recovered"] is True
    assert failovers[0]["replacement_node"] == "NODE-001"

    updated_job = queue.get_job(job.job_id)
    assert updated_job.assigned_node_id == "NODE-001"
    assert updated_job.retry_count == 1
    assert len(updated_job.checkpoints) == 1


# ------------------------------------------------------------------------------
# Test 12: Distributed Audit & Observability (34.19, 34.20, 34.29)
# ------------------------------------------------------------------------------
def test_audit_and_observability():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    queue = JobQueueManager(sched)
    audit = DistributedAuditTrail()
    obs = ClusterObservability(reg, audit, queue)

    audit.record_event(
        user_id="lead-analyst@garuda.internal",
        request_id="REQ-OBS-01",
        action="INFERENCE",
        policy_decision="ALLOW",
        selected_node="NODE-001",
        target_model="qwen-local",
        data_classification="CONFIDENTIAL",
        data_zone="RESTRICTED_AI",
        latency_ms=34.1,
    )

    metrics = obs.get_cluster_dashboard_metrics()
    assert metrics["nodes"]["total"] >= 3
    assert metrics["gpu"]["total_vram_gb"] >= 32.0
    assert metrics["system_status"] in ("HEALTHY", "DEGRADED")

    topology = obs.get_node_map_topology()
    assert len(topology["nodes"]) >= 4
    assert len(topology["links"]) >= 3


# ------------------------------------------------------------------------------
# Test 13: Node-Level Governance & Quarantined Refusal (34.21, 34.31)
# ------------------------------------------------------------------------------
def test_node_governance_and_quarantined_refusal():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)

    # NODE-004-QUARANTINED must never receive any workload
    quarantined = reg.get_node("NODE-004-QUARANTINED")
    assert quarantined.trust_level == NodeTrust.QUARANTINED

    req = WorkloadRequest(
        request_id="REQ-QUARANTINE-TEST",
        capability="chat",
        caller_id="tester",
    )
    dec = sched.schedule(req)
    assert dec.selected_node_id != "NODE-004-QUARANTINED"
    assert "QUARANTINED" in dec.rejected_reasons.get("NODE-004-QUARANTINED", "")


# ------------------------------------------------------------------------------
# Test 14: Offline / Partition Mode (34.22)
# ------------------------------------------------------------------------------
def test_offline_partition_mode():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    sched.set_air_gapped_mode(True)

    # Local request succeeds
    local_req = WorkloadRequest(
        request_id="REQ-LOCAL",
        capability="chat",
        required_model="qwen-local",
        data_classification=DataClassification.CONFIDENTIAL,
    )
    local_dec = sched.schedule(local_req)
    assert local_dec.scheduled is True
    assert local_dec.selected_node_id is not None


# ------------------------------------------------------------------------------
# Test 15: Performance Benchmarks (34.24, 34.36)
# ------------------------------------------------------------------------------
def test_performance_benchmarks():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    bm = ClusterBenchmarker(sched)

    results = bm.run_scheduling_benchmark(request_count=30)
    assert results["request_count"] == 30
    assert results["single_node"]["throughput_req_sec"] > 0
    assert results["distributed_fabric"]["throughput_req_sec"] > 0
    assert len(results["distributed_fabric"]["nodes_utilized"]) >= 2
    assert "throughput_improvement_pct" in results["speedup"]


# ------------------------------------------------------------------------------
# Test 16: Security Testing Suite (34.25, 34.38)
# ------------------------------------------------------------------------------
def test_security_suite():
    reg = NodeRegistry()
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    bus = SecureInterNodeBus()

    # 1. Unauthorized node enrollment approval blocked
    with pytest.raises(ValueError):
        reg.approve_enrollment("NONEXISTENT-REQ")

    # 2. Forged public key blocked
    assert reg.verify_node_identity("NODE-001", "FORGED-PUBKEY") is False

    # 3. Forged envelope HMAC blocked
    env = bus.create_envelope("R1", "NODE-001", "NODE-002", NetworkZone.INTERNAL_AI, "J1", {})
    env.signature = "TAMPERED-SIGNATURE"
    valid, msg = bus.verify_envelope(env)
    assert valid is False
    assert "Invalid cryptographic HMAC signature" in msg


# ------------------------------------------------------------------------------
# Test 17: SIH Golden Flagship Demonstrations 1 through 6 (34.39–34.45)
# ------------------------------------------------------------------------------
def test_all_sih_flagship_demos():
    reg = NodeRegistry()
    health = NodeHealthManager(reg)
    model_mgr = ModelPlacementManager(reg)
    sched = WorkloadScheduler(reg, model_mgr)
    queue = JobQueueManager(sched)
    audit = DistributedAuditTrail()
    demos = SIHFlagshipDemoRunner(reg, sched, queue, health, audit, model_mgr)

    # Demo 1: Distributed inference
    d1 = demos.run_demo_1_distributed_inference()
    assert d1["status"] == "PASSED"
    assert d1["success"] is True

    # Demo 2: Resource-aware scheduling (VRAM constrained)
    d2 = demos.run_demo_2_resource_aware_scheduling()
    assert d2["status"] == "PASSED"
    assert d2["selected_node"] == "NODE-002"
    assert d2["node_a_status"]["scheduling_result"] == "DENIED"

    # Demo 3: Sovereign data placement
    d3 = demos.run_demo_3_sovereign_data_placement()
    assert d3["status"] == "PASSED"
    assert d3["selected_node"] == "NODE-001"

    # Demo 4: Node failure and failover
    d4 = demos.run_demo_4_node_failure_and_failover()
    assert d4["status"] == "PASSED"
    assert d4["success"] is True
    assert d4["recovered_node"] == "NODE-001"

    # Demo 5: Air-gapped partition mode
    d5 = demos.run_demo_5_air_gapped_mode()
    assert d5["status"] == "PASSED"
    assert d5["success"] is True

    # Demo 6: End-to-end control plane story
    d6 = demos.run_demo_6_complete_control_plane_chain()
    assert d6["status"] == "PASSED"
    assert d6["success"] is True
    assert len(d6["pipeline_trace"]) == 9


# ------------------------------------------------------------------------------
# Test 18: FastAPI REST Endpoints (Section 34.23)
# ------------------------------------------------------------------------------
def test_fastapi_rest_endpoints(client):
    # GET /api/v1/fabric/nodes
    res = client.get("/api/v1/fabric/nodes")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 3

    # POST /api/v1/fabric/schedule
    sched_res = client.post(
        "/api/v1/fabric/schedule",
        json={"capability": "chat", "model": "qwen-local", "caller_id": "test-user"},
    )
    assert sched_res.status_code == 200
    sched_data = sched_res.json()
    assert sched_data["scheduled"] is True
    assert sched_data["selected_node_id"] is not None

    # GET /api/v1/fabric/observability/metrics
    metrics_res = client.get("/api/v1/fabric/observability/metrics")
    assert metrics_res.status_code == 200
    assert "gpu" in metrics_res.json()

    # POST /api/v1/fabric/demos/run/1
    demo_res = client.post("/api/v1/fabric/demos/run/1")
    assert demo_res.status_code == 200
    assert demo_res.json()["status"] == "PASSED"
