# Garuda Phase 35: Autonomous AI Orchestration, Self-Optimization & Self-Healing Operations

## 1. Executive Summary & Objective

**Phase 35** elevates Garuda from a distributed compute fabric (Phase 34) into a self-monitoring, self-optimizing, and self-healing autonomous AI platform. Under the sovereign constraints established in Phase 33 Governance and Phase 34 Multi-Node Fabric, Garuda autonomously:
1. **Monitors** distributed operational telemetry (OpenTelemetry-aligned correlated traces & 8 metric tiers).
2. **Predicts** workload pressure and saturation using statistical forecasting ($dQ/dt$).
3. **Optimizes** request dispatch and model lifecycle (safe prewarming, LRU unloading, backpressure queue controls).
4. **Recovers** from known, allowlisted failures deterministically with post-action health verification and reversible rollback.
5. **Enforces Bounded Autonomy** across three configurable execution modes (`OBSERVE`, `RECOMMEND_AND_APPROVE`, `BOUNDED_AUTOMATION`) with hard safety barriers preventing arbitrary command execution or privilege self-granting.

---

## 2. Target Closed-Loop Architecture

The Garuda Autonomous Control Plane operates as a closed feedback loop:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              GARUDA AUTONOMOUS CONTROL PLANE                           │
│                                                                                        │
│   OBSERVE  ──►  DIAGNOSE  ──►  PLAN  ──►  CHECK POLICY  ──►  AUTHORIZE                 │
│      ▲                                                           │                     │
│      │                                                           ▼                     │
│   RETAIN/  ◄──  MEASURE   ◄──  VERIFY ◄────── EXECUTE ◄──────────┘                     │
│   ROLLBACK      IMPACT         HEALTH     (Allowlist Only)                             │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Subordinate Dispatch
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        DISTRIBUTED SOVEREIGN AI FABRIC (Phase 34)                      │
│                                                                                        │
│   Node A (RTX 4060 - 8GB)    Node B (RTX 4090 - 24GB)    Node C (CPU / Storage)        │
│   Local LLM & Reranking      Frontier & Vision Compute   Vector Store & Batch Ingest   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Breakdown (Modules A through P)

### Module A: Unified Telemetry & System Awareness
- **Trace Correlator**: OpenTelemetry-aligned spans correlating frontend requests, API routing, governance policy evaluation, model inference, and audit ledger commits under a single `trace_id`.
- **8 Metric Categories**:
  - `Application`: Request volume, error rates, P95 latency, uptime.
  - `AI Inference`: Time-to-first-token (TTFT), tokens/second, cold/warm start times.
  - `GPU`: Total/used/free VRAM, utilization ratio, GPU temperature.
  - `System`: Host CPU usage, RAM utilization, storage headroom, network throughput.
  - `Queues`: Depth, running concurrency, wait time, retry counts.
  - `RAG`: Chunk parsing time, embedding throughput, retrieval latency.
  - `Agents`: Active durable workflows, tool calls, completion rates.
  - `Governance`: Policy checks, denials, pending approvals, air-gap status.

### Module B: Service Objectives & Performance Baselines
- Loaded from JSON benchmarks (`benchmarks/baseline.json`, `inference.json`, `rag.json`, `scheduler.json`, `recovery.json`).
- Tracks SLI adherence against strict SLO targets (e.g. API P95 $\le$ 100ms, TTFT P95 $\le$ 80ms, availability $\ge$ 99.9%).

### Module C: Predictive Workload Management (`WorkloadPredictor`)
- Evaluates moving arrival velocity ($dQ/dt = Q_t - Q_{t-1}$) and historical request rates.
- Generates structured demand projections:
  - `predicted_queue_depth`
  - `expected_resource_pressure` (`NORMAL`, `MEDIUM`, `HIGH`)
  - `model_warmup_recommended` (validated against free VRAM headroom)
  - `additional_worker_needed` (`NO`, `POSSIBLE`, `YES`)
  - Statistical confidence score.

### Module D: Self-Optimizing Workload Scheduler (`SelfOptimizingScheduler`)
- Combines hard Phase 33 governance eligibility gates with dynamic scoring:
  $$\text{Score}(n, j) = w_1 P_{n,j} + w_2 R_{n,j} + w_3 L_{n,j} + w_4 H_n - w_5 Q_n - w_6 C_{n,j}$$
  - $P$: Hard policy gate (ineligible nodes receive 0 score and are rejected).
  - $R$: Resource suitability (available VRAM/RAM).
  - $L$: Data locality (restricted sovereign zone matches).
  - $H$: Trust and health status.
  - $Q$: Dynamic queue pressure incorporating forecasted arrival velocity.
  - $C$: Network transfer and compute cost.

### Module E: Intelligent Model Lifecycle (`ModelLifecycleManager`)
- Evaluates safe speculative prewarming without inducing out-of-memory (OOM) failures on local hardware (RTX 4060 8GB VRAM ceiling).
- Implements LRU idle model unloading to reclaim VRAM headroom when new high-priority models arrive.

### Module F: Queue Optimization & Backpressure Controls (`QueueOptimizer`)
- Multi-tier priority scheduling: `CRITICAL` (Incident response) > `HIGH` (Interactive user requests) > `NORMAL` (Standard RAG/Chat) > `LOW` (Batch analysis) > `BACKGROUND` (Indexing).
- Per-user fair concurrency limits and automatic load-shedding of low-priority workloads during queue saturation.

### Module G: Allowlisted Self-Healing Engine (`AllowlistedSelfHealingEngine`)
- Strictly allowlisted failure remediation catalog:
  - `WORKER_HEARTBEAT_MISSING` $\rightarrow$ Mark unavailable, drain active connections, verify replacement node.
  - `INFERENCE_ENDPOINT_UNHEALTHY` $\rightarrow$ Reinitialize service container context and verify probe health.
  - `JOB_TIMED_OUT` $\rightarrow$ Cancel safely and retry only idempotent operations with bounded retry budgets.
  - `QUEUE_OVERLOADED` $\rightarrow$ Apply backpressure and shed low-priority batch workloads.
  - `SECURITY_VIOLATION` $\rightarrow$ Quarantine node, isolate network egress, trigger security incident.

### Module H: Durable Multi-Agent Workflows (`DurableWorkflowEngine`)
- Resilient multi-step execution plans (`parse_document` $\rightarrow$ `extract_evidence` $\rightarrow$ `retrieve_rag` $\rightarrow$ `generate_draft` $\rightarrow$ `validate_output` $\rightarrow$ `export_report` $\rightarrow$ `record_audit_result`).
- Checkpointed state persistence with just-in-time human authorization gates before sensitive operations (e.g. evidence exports).

### Module I: Bounded Autonomy & Governance Bridge (`AutonomyGovernanceBridge`)
- 3 Autonomy Modes:
  - **Mode 1 (Observe)**: Telemetry and anomaly detection without changing state.
  - **Mode 2 (Recommend & Approve)**: Generates structured action proposals and awaits human administrator sign-off.
  - **Mode 3 (Bounded Automation)**: Automatically executes explicitly allowlisted, low-risk, reversible actions within pre-configured budgets.
- Strict Forbidden Action Allowlist:
  - `disable_audit_logging` $\rightarrow$ Permanently blocked.
  - `bypass_authorization` $\rightarrow$ Permanently blocked.
  - `execute_unrestricted_shell` $\rightarrow$ Permanently blocked.
  - `transfer_restricted_data_to_unapproved_node` $\rightarrow$ Permanently blocked.

### Module J: Action Pipeline, Executor & Reversible Rollback (`ActionExecutor`)
- Validates pre-conditions, executes deterministic allowlisted handlers, conducts post-action health verification, and records reversible state snapshots for automated or manual rollbacks.

### Module K: System Anomaly Detector (`SystemAnomalyDetector`)
- Compares live telemetry against moving statistical thresholds:
  - Latency spikes ($> 2.5\times$ baseline).
  - VRAM pressure ($> 88\%$ capacity).
  - Queue overloads.
  - Spurious authorization bursts ($> 20$ policy denials/min).

### Module L: Learning from Previous Actions & Outcome Feedback (`ActionOutcomeEvaluator`)
- Records pre- and post-action states, calculates net latency savings vs VRAM costs, and computes empirical effectiveness rankings for candidate operational actions.

### Module M: Safe Optimization Experiments (`OptimizationExperimentRunner`)
- Controlled A/B trials comparing proposed configurations against baselines with automatic rollback if latency degrades or VRAM limits ($> 7.5\text{ GB}$) are breached.

### Module N: Controlled Capacity Scaling (`CapacityManager`)
- Enforces strict upper/lower bounds on worker pools (min: 1, max: 4), concurrent inference pipelines, and cooldown timer enforcement ($60\text{s}$) to prevent oscillation.

### Module O: Operational Incident Lifecycle (`IncidentLifecycleManager`)
- Full incident lifecycle tracking: `DETECTED` $\rightarrow$ `CLASSIFIED` $\rightarrow$ `RISK_ASSESSED` $\rightarrow$ `CONTAINMENT` $\rightarrow$ `RECOVERY` $\rightarrow$ `VERIFICATION` $\rightarrow$ `RESOLVED`.
- Quarantined security nodes are prohibited from auto-resolution without explicit human security officer sign-off.

### Module P: Operations Dashboard (`/operations`)
- Next.js UI providing live KPI cards, autonomy mode selector, closed-loop visual pipeline, action approval table with interactive Approve/Execute/Rollback triggers, workload forecasting, telemetry metrics, and the SIH Flagship Demo runner.

---

## 4. Verification & Pytest Results

Comprehensive test suite in `tests/phase35/test_phase35_comprehensive.py`:
- Total Tests: **18 / 18 passing (100%)**
- Execution Time: **0.36 seconds**
- Test Coverage:
  1. `test_unified_telemetry_pipeline` (Passed)
  2. `test_service_baselines_and_slos` (Passed)
  3. `test_workload_forecasting` (Passed)
  4. `test_self_optimizing_scheduler` (Passed)
  5. `test_model_lifecycle_management` (Passed)
  6. `test_queue_optimization_and_backpressure` (Passed)
  7. `test_allowlisted_self_healing` (Passed)
  8. `test_durable_workflow_orchestration` (Passed)
  9. `test_governance_modes_and_boundaries` (Passed)
  10. `test_action_executor_and_rollback` (Passed)
  11. `test_system_anomaly_detector` (Passed)
  12. `test_action_feedback_learning` (Passed)
  13. `test_optimization_experiments_and_rollback` (Passed)
  14. `test_capacity_manager_and_cooldown` (Passed)
  15. `test_incident_response_lifecycle` (Passed)
  16. `test_safety_invariants_and_boundaries` (Passed)
  17. `test_sih_flagship_demo` (Passed)
  18. `test_rest_api_control_plane` (Passed)
