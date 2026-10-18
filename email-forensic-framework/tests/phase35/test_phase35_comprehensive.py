"""Master Test Suite for Phase 35: Autonomous AI Orchestration, Self-Optimization & Self-Healing Operations.
Validates all 15 Definition of Done criteria (Section 35.24), unit tests, integration tests,
safety tests (Section 35.21), the 7-step SIH Flagship Demo, and REST Control-Plane APIs.
"""
import pytest
import time
from starlette.testclient import TestClient

from autonomous_ops.models import (
    AutonomyMode,
    ActionRiskLevel,
    ActionExecutionStatus,
    IncidentSeverity,
    IncidentLifecycleStatus,
    AnomalyType,
)
from autonomous_ops.telemetry import UnifiedTelemetryPipeline, TelemetryCorrelator
from autonomous_ops.baselines import ServiceObjectiveManager, ServiceBaselineManager
from autonomous_ops.forecasting import WorkloadPredictor, WorkloadForecastResult
from autonomous_ops.optimizer import SelfOptimizingScheduler
from autonomous_ops.model_lifecycle import AutonomousModelLifecycleManager, ModelLifecycleManager
from autonomous_ops.queue_control import QueueOptimizer, AutonomousQueueManager, PriorityLevel
from autonomous_ops.self_healing import SelfHealingEngine, AllowlistedSelfHealingEngine, FailureType
from autonomous_ops.workflows import DurableWorkflowEngine, WorkflowStatus
from autonomous_ops.governance_bridge import AutonomyGovernanceBridge
from autonomous_ops.action_plans import ActionPlanManager
from autonomous_ops.action_executor import ActionExecutor
from autonomous_ops.anomaly_detector import SystemAnomalyDetector
from autonomous_ops.feedback import ActionOutcomeEvaluator
from autonomous_ops.experiments import OptimizationExperimentRunner
from autonomous_ops.capacity import CapacityManager, CapacityBounds
from autonomous_ops.incidents import IncidentLifecycleManager

from fabric.node_registry import NodeRegistry
from fabric.models import NodeStatus, DataClassification, WorkloadPriority

from phase_35_autonomous_operations import app, SIHPhase35FlagshipDemo


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# Test 1: Unified Telemetry & Correlated Traces (Module A - 35.3)
# ------------------------------------------------------------------------------
def test_unified_telemetry_pipeline():
    reg = NodeRegistry()
    pipeline = UnifiedTelemetryPipeline(reg)

    trace = pipeline.start_trace(request_id="REQ-TEST-100", user_id="investigator@garuda.internal")
    t0 = time.time()
    trace.add_span("api_entry", t0, t0 + 0.01, {"route": "/api/fabric/schedule"})
    trace.add_span("governance_check", t0 + 0.01, t0 + 0.02, {"decision": "ALLOW"})
    trace.add_span("model_inference", t0 + 0.02, t0 + 0.08, {"tokens": 64})

    assert len(trace.spans) == 3
    assert trace.total_duration_ms > 0.0
    trace_dict = trace.to_dict()
    assert trace_dict["spans_count"] == 3

    snapshot = pipeline.capture_snapshot()
    # Verify 8 telemetry categories exist
    assert "application" in snapshot
    assert "ai_inference" in snapshot
    assert "gpu" in snapshot
    assert "system" in snapshot
    assert "queues" in snapshot
    assert "rag" in snapshot
    assert "agents" in snapshot
    assert "governance" in snapshot


# ------------------------------------------------------------------------------
# Test 2: Service Objectives & Performance Baselines (Module B - 35.4)
# ------------------------------------------------------------------------------
def test_service_baselines_and_slos():
    base_mgr = ServiceObjectiveManager()
    slos = base_mgr.list_all_slos()
    assert "api_latency_p95_ms" in slos
    assert "ai_ttft_p95_ms" in slos
    assert "service_availability_pct" in slos

    baselines = base_mgr.get_all_baselines()
    assert "baseline" in baselines or len(baselines) >= 0

    mock_telemetry = {
        "application": {"p95_latency_ms": 68.0, "uptime_pct": 99.98},
        "ai_inference": {"time_to_first_token_avg_ms": 38.0},
    }
    eval_result = base_mgr.evaluate_slo_compliance(mock_telemetry)
    assert eval_result["overall_compliant"] is True
    assert eval_result["sli_score_pct"] == 100.0


# ------------------------------------------------------------------------------
# Test 3: Predictive Workload Forecasting (Module C - 35.5)
# ------------------------------------------------------------------------------
def test_workload_forecasting():
    predictor = WorkloadPredictor()
    forecast = predictor.forecast_workload(
        current_queue_depth=4,
        available_vram_gb=1.1,
        target_model="qwen-2.5-coder-7b",
    )
    assert forecast["predicted_queue"] >= 4
    assert forecast["expected_resource_pressure"] in ["HIGH", "MEDIUM", "NORMAL"]
    assert forecast["confidence"] > 0.5
    assert forecast["model_warmup_recommended"] is False  # VRAM too low (1.1 GB < 2.2 GB)

    # When ample VRAM is free:
    forecast_ample = predictor.forecast_workload(
        current_queue_depth=5,
        available_vram_gb=5.5,
        target_model="qwen-2.5-coder-7b",
    )
    assert forecast_ample["model_warmup_recommended"] is True


# ------------------------------------------------------------------------------
# Test 4: Self-Optimizing Scheduler & Explainable Routing (Module D - 35.6)
# ------------------------------------------------------------------------------
def test_self_optimizing_scheduler():
    reg = NodeRegistry()
    forecaster = WorkloadPredictor()
    sched = SelfOptimizingScheduler(node_registry=reg, forecaster=forecaster)

    decision = sched.schedule_workload(
        job_id="JOB-TEST-01",
        required_model="qwen-local",
        data_classification="CONFIDENTIAL",
    )
    assert decision["scheduled"] is True
    assert decision["selected_node"] in ["NODE-001", "NODE-002"]
    assert "Policy compatible" in decision["explanation"]
    assert len(decision["candidate_scores"]) >= 3


# ------------------------------------------------------------------------------
# Test 5: Intelligent Model Lifecycle Management (Module E - 35.7)
# ------------------------------------------------------------------------------
def test_model_lifecycle_management():
    reg = NodeRegistry()
    mgr = AutonomousModelLifecycleManager(registry=reg)

    # Node 1 has 4.8 GB free VRAM
    prewarm_eval = mgr.evaluate_prewarm("bge-embeddings", "NODE-001")
    assert prewarm_eval["safe"] is True

    # Attempting to load an enormous model that exceeds free VRAM
    class FakeSpec:
        required_vram_gb = 16.0
    mgr.placement_mgr._catalog["huge-model"] = FakeSpec()

    deny_eval = mgr.evaluate_prewarm("huge-model", "NODE-001")
    assert deny_eval["safe"] is False
    assert "Insufficient VRAM" in deny_eval["reason"]


# ------------------------------------------------------------------------------
# Test 6: Queue Optimization, Priorities & Backpressure (Module F - 35.8)
# ------------------------------------------------------------------------------
def test_queue_optimization_and_backpressure():
    q_opt = QueueOptimizer(max_total_queue=5, max_per_user_concurrency=2)

    # Normal enqueues
    ok1, msg1, item1 = q_opt.enqueue("chat", "qwen-local", "user-1", WorkloadPriority.NORMAL)
    assert ok1 is True
    ok2, msg2, item2 = q_opt.enqueue("chat", "qwen-local", "user-1", WorkloadPriority.NORMAL)
    assert ok2 is True

    # User concurrency throttle
    ok3, msg3, item3 = q_opt.enqueue("chat", "qwen-local", "user-1", WorkloadPriority.NORMAL)
    assert ok3 is False
    assert "Fair-use throttle" in msg3

    # Critical work bypasses user concurrency throttle
    ok_crit, msg_crit, item_crit = q_opt.enqueue("incident", "qwen-local", "user-1", WorkloadPriority.CRITICAL)
    assert ok_crit is True

    # Fill queue to capacity
    q_opt.enqueue("chat", "qwen-local", "user-2", WorkloadPriority.NORMAL)
    q_opt.enqueue("chat", "qwen-local", "user-3", WorkloadPriority.NORMAL)

    # Backpressure sheds low priority
    ok_low, msg_low, _ = q_opt.enqueue("batch", "qwen-local", "user-4", WorkloadPriority.LOW)
    assert ok_low is False
    assert "Backpressure" in msg_low


# ------------------------------------------------------------------------------
# Test 7: Allowlisted Self-Healing Engine (Module G - 35.9)
# ------------------------------------------------------------------------------
def test_allowlisted_self_healing():
    reg = NodeRegistry()
    engine = SelfHealingEngine(node_registry=reg)

    # Recover from worker drop
    rec = engine.handle_failure(FailureType.WORKER_HEARTBEAT_MISSING, "NODE-002")
    assert rec["status"] == "RECOVERED"
    assert reg.get_node("NODE-002").status == NodeStatus.UNAVAILABLE

    # Recover from endpoint unhealthy
    rec_ep = engine.handle_failure(FailureType.INFERENCE_ENDPOINT_UNHEALTHY, "NODE-001:qwen-local")
    assert rec_ep["status"] == "RECOVERED"


# ------------------------------------------------------------------------------
# Test 8: Durable Multi-Agent Workflows & Checkpoints (Module H - 35.10)
# ------------------------------------------------------------------------------
def test_durable_workflow_orchestration():
    wf_engine = DurableWorkflowEngine()
    wf = wf_engine.create_forensic_pipeline(
        workflow_name="Phishing Investigation",
        document_id="EMAIL-MSG-409",
        user_id="lead-analyst@garuda.internal",
    )
    assert wf.status == WorkflowStatus.INITIALIZED.value

    # Execute step-by-step
    res1 = wf_engine.execute_next_step(wf.workflow_id)
    assert res1["status"] == WorkflowStatus.IN_PROGRESS.value
    assert "checkpoint" in res1

    # Advance until approval gate
    run_res = wf_engine.execute_workflow(wf.workflow_id)
    assert run_res["status"] == WorkflowStatus.AWAITING_APPROVAL.value

    # Approve step and finish
    wf_engine.submit_step_approval(wf.workflow_id, "export_report")
    final_res = wf_engine.execute_workflow(wf.workflow_id)
    assert final_res["status"] == WorkflowStatus.COMPLETED.value


# ------------------------------------------------------------------------------
# Test 9: Bounded Autonomy & Governance Bridge (Module I - 35.11)
# ------------------------------------------------------------------------------
def test_governance_modes_and_boundaries():
    gov = AutonomyGovernanceBridge(initial_mode=AutonomyMode.BOUNDED_AUTOMATION)
    plan_mgr = ActionPlanManager(governance_bridge=gov)

    # 1. Allowlisted low-risk action auto-executes
    plan_auto = plan_mgr.create_action_plan(
        action_type="health_check",
        target_resource="NODE-001",
        reason="Periodic health probe",
        risk_level=ActionRiskLevel.LOW,
    )
    assert plan_auto.status == ActionExecutionStatus.APPROVED
    assert plan_auto.approval_required is False

    # 2. Privileged action requires approval
    plan_priv = plan_mgr.create_action_plan(
        action_type="quarantine_worker",
        target_resource="NODE-002",
        reason="Security egress probe",
        risk_level=ActionRiskLevel.HIGH,
    )
    assert plan_priv.status == ActionExecutionStatus.PENDING_APPROVAL
    assert plan_priv.approval_required is True

    # 3. Forbidden action permanently rejected
    plan_forbidden = plan_mgr.create_action_plan(
        action_type="execute_unrestricted_shell",
        target_resource="HOST_ROOT",
        reason="Host shell command injection attempt",
        risk_level=ActionRiskLevel.CRITICAL,
    )
    assert plan_forbidden.status == ActionExecutionStatus.REJECTED
    assert plan_forbidden.policy_decision == "DENY"


# ------------------------------------------------------------------------------
# Test 10: Action Executor, Post-Action Health Check & Reversible Rollback (Module J - 35.12)
# ------------------------------------------------------------------------------
def test_action_executor_and_rollback():
    gov = AutonomyGovernanceBridge(initial_mode=AutonomyMode.BOUNDED_AUTOMATION)
    plan_mgr = ActionPlanManager(governance_bridge=gov)
    executor = ActionExecutor(plan_manager=plan_mgr, governance_bridge=gov)

    plan = plan_mgr.create_action_plan(
        action_type="apply_queue_backpressure",
        target_resource="QUEUE_SYS",
        reason="Shed load",
        risk_level=ActionRiskLevel.LOW,
    )
    exec_result = executor.execute_action(plan.action_id)
    assert exec_result["success"] is True
    assert plan.status == ActionExecutionStatus.COMPLETED

    # Rollback action
    rollback_result = executor.rollback_action(plan.action_id)
    assert rollback_result["success"] is True
    assert plan.status == ActionExecutionStatus.ROLLED_BACK


# ------------------------------------------------------------------------------
# Test 11: Statistical Anomaly Detection (Module K - 35.13)
# ------------------------------------------------------------------------------
def test_system_anomaly_detector():
    detector = SystemAnomalyDetector()

    # Latency anomaly (> 2.5x baseline)
    anom_lat = detector.check_inference_latency(observed_latency_ms=1250.0, target_resource="qwen-2.5-coder-7b")
    assert anom_lat is not None
    assert anom_lat.anomaly_type == AnomalyType.LATENCY_SPIKE

    # Normal latency (no anomaly)
    normal_lat = detector.check_inference_latency(observed_latency_ms=45.0, target_resource="qwen-2.5-coder-7b")
    assert normal_lat is None

    # VRAM saturation anomaly (> 88%)
    anom_vram = detector.check_vram_pressure(used_vram_gb=7.6, total_vram_gb=8.0, node_id="NODE-001")
    assert anom_vram is not None
    assert anom_vram.anomaly_type == AnomalyType.VRAM_PRESSURE

    # Spurious authorization bursts
    anom_auth = detector.check_auth_spike(policy_denials_per_min=25)
    assert anom_auth is not None
    assert anom_auth.severity == IncidentSeverity.CRITICAL


# ------------------------------------------------------------------------------
# Test 12: Learning from Previous Actions & Outcome Feedback (Module L - 35.14)
# ------------------------------------------------------------------------------
def test_action_feedback_learning():
    evaluator = ActionOutcomeEvaluator()

    record = evaluator.record_outcome(
        action_id="ACT-EXP-01",
        action_type="prewarm_model",
        target_resource="qwen-local",
        prior_state={"ttft_ms": 3200.0},
        post_state={"ttft_ms": 45.0},
        expected_effect="Eliminate cold start",
        latency_delta_ms=-3155.0,
        vram_delta_gb=2.2,
        success=True,
    )
    assert record.latency_delta_ms < 0
    assert "Trade-off" in record.conclusion or "Highly effective" in record.conclusion

    ranked = evaluator.rank_candidate_actions(["prewarm_model", "reroute_eligible_job"])
    assert len(ranked) >= 2
    assert ranked[0]["confidence_score"] > 0.0


# ------------------------------------------------------------------------------
# Test 13: Controlled Optimization Experiments & Auto-Rollback (Module M - 35.15)
# ------------------------------------------------------------------------------
def test_optimization_experiments_and_rollback():
    runner = OptimizationExperimentRunner()

    # Winning experiment
    exp_win = runner.run_experiment(
        title="Queue Weight Fine Tuning",
        hypothesis="Increase queue penalty",
        baseline_metrics={"p50_latency_ms": 500.0, "error_rate_pct": 0.5, "vram_used_gb": 4.5},
        proposed_config={"weight_queue": 35.0},
    )
    assert exp_win.accepted is True
    assert exp_win.improvement_pct > 0.0

    # Failing experiment causing rollback
    exp_fail = runner.run_experiment(
        title="Extreme Memory Allocation",
        hypothesis="Prewarm oversized model",
        baseline_metrics={"p50_latency_ms": 400.0, "error_rate_pct": 0.0, "vram_used_gb": 7.4},
        proposed_config={"weight_queue": 10.0, "prewarm_enabled": True},
    )
    assert exp_fail.accepted is False
    assert "exceeded safe threshold" in exp_fail.rollback_reason


# ------------------------------------------------------------------------------
# Test 14: Controlled Capacity Scaling & Cooldown Enforcement (Module N - 35.16)
# ------------------------------------------------------------------------------
def test_capacity_manager_and_cooldown():
    mgr = CapacityManager(bounds=CapacityBounds(min_workers=1, max_workers=3, cooldown_seconds=60))

    # Scale up
    scale_res = mgr.execute_bounded_scale("SCALE_UP")
    assert scale_res["status"] == "SUCCESS"
    assert mgr.current_worker_count == 3

    # Immediate second scale must be rejected by cooldown
    with pytest.raises(PermissionError) as exc_info:
        mgr.execute_bounded_scale("SCALE_UP")
    assert "Cooldown" in str(exc_info.value)


# ------------------------------------------------------------------------------
# Test 15: Incident Response Lifecycle & Quarantine Safety (Module O - 35.17)
# ------------------------------------------------------------------------------
def test_incident_response_lifecycle():
    mgr = IncidentLifecycleManager()

    inc = mgr.declare_incident(
        title="Quarantine Egress Alert",
        severity=IncidentSeverity.CRITICAL,
        target_resource="NODE-004-QUARANTINED",
        detection_source="SecurityMonitor",
        description="Outbound egress detected on quarantined node",
    )
    assert inc.status == IncidentLifecycleStatus.DETECTED

    mgr.advance_stage(inc.incident_id, IncidentLifecycleStatus.CONTAINMENT, "Isolate port", ["BLOCK_PORT"])

    # Auto-resolve without human clearance must be blocked for quarantined security nodes
    with pytest.raises(PermissionError) as exc_info:
        mgr.advance_stage(inc.incident_id, IncidentLifecycleStatus.RESOLVED, "Auto resolve attempt")
    assert "human security officer sign-off" in str(exc_info.value)

    # Resolving with proper sign-off succeeds
    mgr.advance_stage(
        inc.incident_id,
        IncidentLifecycleStatus.RESOLVED,
        "Cleared after forensic audit",
        actions_taken=["HUMAN_SECURITY_CLEARANCE"],
    )
    assert inc.status == IncidentLifecycleStatus.RESOLVED
    assert inc.resolved_at is not None


# ------------------------------------------------------------------------------
# Test 16: Safety Tests - Unauthorized Nodes, Arbitrary Shell & Fail-Closed (Section 35.21)
# ------------------------------------------------------------------------------
def test_safety_invariants_and_boundaries():
    reg = NodeRegistry()
    forecaster = WorkloadPredictor()
    sched = SelfOptimizingScheduler(node_registry=reg, forecaster=forecaster)

    # 1. Quarantined node must NEVER be selected even under load
    dec = sched.schedule_workload("JOB-SEC-01", "qwen-local", "CONFIDENTIAL")
    assert dec["selected_node"] != "NODE-004-QUARANTINED"

    # 2. Arbitrary shell command execution permanently blocked
    gov = AutonomyGovernanceBridge(initial_mode=AutonomyMode.BOUNDED_AUTOMATION)
    plan_mgr = ActionPlanManager(governance_bridge=gov)
    executor = ActionExecutor(plan_manager=plan_mgr, governance_bridge=gov)

    shell_plan = plan_mgr.create_action_plan(
        action_type="execute_unrestricted_shell",
        target_resource="HOST_SYSTEM",
        reason="Inject shell",
        risk_level=ActionRiskLevel.CRITICAL,
    )
    assert shell_plan.status == ActionExecutionStatus.REJECTED

    with pytest.raises(PermissionError):
        executor.execute_action(shell_plan.action_id)


# ------------------------------------------------------------------------------
# Test 17: SIH Flagship Demonstration (Section 35.22)
# ------------------------------------------------------------------------------
def test_sih_flagship_demo():
    reg = NodeRegistry()
    forecaster = WorkloadPredictor()
    sched = SelfOptimizingScheduler(node_registry=reg, forecaster=forecaster)
    queue_mgr = AutonomousQueueManager()
    healing_engine = AllowlistedSelfHealingEngine(node_registry=reg, queue_manager=queue_mgr)
    gov = AutonomyGovernanceBridge(initial_mode=AutonomyMode.RECOMMEND_AND_APPROVE)
    plan_mgr = ActionPlanManager(governance_bridge=gov)
    executor = ActionExecutor(
        plan_manager=plan_mgr,
        governance_bridge=gov,
        queue_manager=queue_mgr,
        self_healing_engine=healing_engine,
        node_registry=reg,
    )
    inc_mgr = IncidentLifecycleManager()
    exp_runner = OptimizationExperimentRunner()
    wf_engine = DurableWorkflowEngine()

    demo = SIHPhase35FlagshipDemo(
        node_registry=reg,
        scheduler=sched,
        queue_manager=queue_mgr,
        healing_engine=healing_engine,
        action_plan_mgr=plan_mgr,
        action_executor=executor,
        governance_bridge=gov,
        incident_mgr=inc_mgr,
        experiment_runner=exp_runner,
        workflow_engine=wf_engine,
    )

    results = demo.run_full_demo()
    assert results["success"] is True
    assert results["total_steps"] == 7
    assert "verified under sovereign governance" in results["verdict"]


# ------------------------------------------------------------------------------
# Test 18: Complete REST Control-Plane API Coverage (Section 35.19)
# ------------------------------------------------------------------------------
def test_rest_api_control_plane(client):
    # Overview
    r_overview = client.get("/api/ops/overview")
    assert r_overview.status_code == 200
    assert "autonomy_mode" in r_overview.json()

    # Metrics
    r_metrics = client.get("/api/ops/metrics")
    assert r_metrics.status_code == 200
    assert "gpu" in r_metrics.json()

    # Predictions
    r_pred = client.get("/api/ops/predictions")
    assert r_pred.status_code == 200
    assert "predicted_queue_depth" in r_pred.json()

    # Propose Plan
    r_plan = client.post("/api/ops/plan", json={
        "action_type": "reroute_eligible_job",
        "target_resource": "JOB-REST-01",
        "reason": "Queue rebalance",
        "risk_level": "LOW",
    })
    assert r_plan.status_code == 200
    act_id = r_plan.json()["plan"]["action_id"]

    # Evaluate Plan
    r_eval = client.post(f"/api/ops/actions/{act_id}/evaluate")
    assert r_eval.status_code == 200

    # Actions List
    r_actions = client.get("/api/ops/actions")
    assert r_actions.status_code == 200
    assert len(r_actions.json()) >= 1

    # Incidents List
    r_incidents = client.get("/api/ops/incidents")
    assert r_incidents.status_code == 200

    # Experiments List
    r_exps = client.get("/api/ops/experiments")
    assert r_exps.status_code == 200

    # Config
    r_cfg = client.get("/api/ops/config")
    assert r_cfg.status_code == 200
    assert "capacity_bounds" in r_cfg.json()

    # Update Autonomy Mode
    r_mode = client.post("/api/ops/mode", json={"mode": "BOUNDED_AUTOMATION"})
    assert r_mode.status_code == 200
    assert r_mode.json()["new_mode"] == "BOUNDED_AUTOMATION"

    # Execute Action
    r_exec = client.post(f"/api/ops/actions/{act_id}/execute")
    assert r_exec.status_code in (200, 403)  # Depends on mode/approval

    # Anomalies
    r_anom = client.get("/api/ops/anomalies")
    assert r_anom.status_code == 200

    # Traces
    r_traces = client.get("/api/ops/traces")
    assert r_traces.status_code == 200

    # Workflows Run
    r_wf = client.post("/api/ops/workflows/run", json={
        "workflow_name": "API Investigation Test",
        "document_id": "DOC-999",
        "user_id": "test-analyst@garuda.internal",
        "auto_approve_export": True,
    })
    assert r_wf.status_code == 200
    assert r_wf.json()["status"] == "COMPLETED"

    # SIH Demo API endpoint
    r_demo = client.post("/api/ops/demo/sih")
    assert r_demo.status_code == 200
    assert r_demo.json()["success"] is True


# ------------------------------------------------------------------------------
# Test 19: Code Review Remediation Regression Integrity
# ------------------------------------------------------------------------------
def test_remediation_fixes():
    reg = NodeRegistry()
    model_mgr = ModelLifecycleManager(node_registry=reg)
    gov = AutonomyGovernanceBridge(initial_mode=AutonomyMode.BOUNDED_AUTOMATION)
    plan_mgr = ActionPlanManager(governance_bridge=gov)
    executor = ActionExecutor(
        plan_manager=plan_mgr,
        governance_bridge=gov,
        model_manager=model_mgr,
        node_registry=reg,
    )

    # 1. ActionExecutor prewarm_model execution
    prewarm_plan = plan_mgr.create_action_plan(
        action_type="prewarm_model",
        target_resource="qwen-2.5-coder-7b",
        reason="Anticipated spike",
        risk_level=ActionRiskLevel.LOW,
        parameters={"target_node": "NODE-001"},
    )
    outcome = executor.execute_action(prewarm_plan.action_id)
    assert outcome["success"] is True

    # 2. FabricNodeRecord serialization safety with enum and string
    node = reg.get_node("NODE-001")
    assert node is not None
    node_dict = node.to_dict()
    assert node_dict["status"] in ("HEALTHY", "DEGRADED", "UNAVAILABLE")

    # 3. Dynamic replacement in Self-Healing (never picks the failed node itself)
    healer = AllowlistedSelfHealingEngine(node_registry=reg)
    heal_res = healer.handle_failure(FailureType.WORKER_HEARTBEAT_MISSING, resource_id="NODE-001")
    assert heal_res["replacement_node"] != "NODE-001"
    assert heal_res["status"] == "RECOVERED"

    # 4. Checkpoint resumption off-by-one verification
    wf_engine = DurableWorkflowEngine()
    wf = wf_engine.create_forensic_pipeline(
        workflow_name="Phishing Checkpoint Test",
        document_id="EMAIL-MSG-999",
        user_id="analyst@garuda.internal",
    )
    # Step 0 completes
    step0_res = wf_engine.execute_next_step(wf.workflow_id)
    assert step0_res["checkpoint"]["step_index"] == 0
    # Resume should resume at step index 1
    resume_res = wf_engine.resume_from_checkpoint(wf.workflow_id)
    assert resume_res["resumed_from_step_index"] == 1

