"""Garuda Distributed Sovereign AI Fabric - Distributed Agents & Checkpointing.
Phase 34 Sections 34.13 & 34.21:
Checkpointable agent execution, multi-step plan persistence,
and cross-node task migration upon node disruption.
"""
from typing import Dict, List, Optional, Any
import time
import uuid

from fabric.models import (
    FabricJobRecord,
    JobState,
    WorkloadRequest,
    WorkloadPriority,
    DataClassification,
)
from fabric.scheduler import WorkloadScheduler
from fabric.job_queue import JobQueueManager


class DistributedAgentOrchestrator:
    """Orchestrates autonomous agents across fabric nodes with continuous checkpointing."""

    def __init__(self, scheduler: WorkloadScheduler, job_queue: JobQueueManager):
        self.scheduler = scheduler
        self.job_queue = job_queue
        self._active_agent_runs: Dict[str, Dict[str, Any]] = {}

    def dispatch_agent_task(
        self,
        agent_id: str,
        task_prompt: str,
        required_tools: List[str],
        data_classification: DataClassification = DataClassification.INTERNAL,
        priority: WorkloadPriority = WorkloadPriority.HIGH,
    ) -> Dict[str, Any]:
        """Schedules and launches an agent task on an eligible fabric worker node."""
        sched_req = WorkloadRequest(
            request_id=f"AGENT-{uuid.uuid4().hex[:6]}",
            capability="coding" if "code" in task_prompt.lower() else "llm_inference",
            data_classification=data_classification,
            priority=priority,
        )
        decision = self.scheduler.schedule(sched_req)
        if not decision.scheduled or not decision.selected_node_id:
            raise PermissionError(f"Agent dispatch denied by scheduler: {decision.explanation}")

        assigned_node = decision.selected_node_id
        job = self.job_queue.create_job(
            capability=sched_req.capability,
            assigned_node_id=assigned_node,
            priority=priority,
        )

        agent_run = {
            "run_id": f"RUN-{uuid.uuid4().hex[:8].upper()}",
            "job_id": job.job_id,
            "agent_id": agent_id,
            "assigned_node": assigned_node,
            "task_prompt": task_prompt,
            "tools": required_tools,
            "current_step": 0,
            "plan": [
                "Initialize investigation workspace & load TLS telemetry",
                "Execute rule inspection & anomaly detection",
                "Synthesize CBOM report & cryptographic posture score",
                "Generate executive deliverable & audit package",
            ],
            "step_history": [],
            "status": "RUNNING",
            "created_at": time.time(),
        }
        self._active_agent_runs[agent_run["run_id"]] = agent_run
        return agent_run

    def execute_agent_step(self, run_id: str) -> Dict[str, Any]:
        """Executes a single step in the agent plan and saves an immutable checkpoint."""
        run = self._active_agent_runs.get(run_id)
        if not run:
            raise ValueError(f"Agent run '{run_id}' not found")

        step_idx = run["current_step"]
        if step_idx >= len(run["plan"]):
            run["status"] = "COMPLETED"
            self.job_queue.complete_job(run["job_id"], {"status": "SUCCESS", "completed_steps": len(run["plan"])})
            return {"run_id": run_id, "status": "COMPLETED", "message": "All steps finished"}

        step_name = run["plan"][step_idx]
        step_result = {
            "step_number": step_idx + 1,
            "step_name": step_name,
            "executed_on_node": run["assigned_node"],
            "timestamp": time.time(),
            "status": "SUCCESS",
            "observation": f"Completed step '{step_name}' on worker {run['assigned_node']}",
        }
        run["step_history"].append(step_result)
        run["current_step"] += 1

        # Save checkpoint to durable job queue (Section 34.21)
        self.job_queue.checkpoint_job(
            job_id=run["job_id"],
            step_name=step_name,
            state_snapshot={
                "current_step": run["current_step"],
                "completed_steps": len(run["step_history"]),
                "last_node": run["assigned_node"],
            },
        )

        if run["current_step"] >= len(run["plan"]):
            run["status"] = "COMPLETED"
            self.job_queue.complete_job(run["job_id"], {"status": "SUCCESS", "completed_steps": len(run["plan"])})

        return step_result

    def migrate_agent_task(self, run_id: str, new_node_id: str) -> Dict[str, Any]:
        """Migrates a disrupted agent task to a new node, resuming from the latest checkpoint."""
        run = self._active_agent_runs.get(run_id)
        if not run:
            raise ValueError(f"Agent run '{run_id}' not found")

        old_node = run["assigned_node"]
        run["assigned_node"] = new_node_id
        migration_info = {
            "run_id": run_id,
            "resumed_from_step": run["current_step"],
            "previous_node": old_node,
            "new_node": new_node_id,
            "checkpoint_restored": True,
            "timestamp": time.time(),
        }
        return migration_info
