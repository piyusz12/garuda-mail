"""Garuda Distributed Sovereign AI Fabric - Job Persistence & Automatic Failover.
Phase 34 Sections 34.17 & 34.18:
Durable job queue, state persistence, checkpoint tracking,
automatic failover, and job resumption across worker nodes.
"""
from typing import Dict, List, Optional, Any
import time
import uuid

from fabric.models import (
    FabricJobRecord,
    JobState,
    WorkloadPriority,
    WorkloadRequest,
    DataClassification,
    NetworkZone,
    SchedulingDecision,
)
from fabric.scheduler import WorkloadScheduler


class JobQueueManager:
    """Manages persistent jobs, execution checkpoints, and automated failover orchestration."""

    def __init__(self, scheduler: WorkloadScheduler):
        self.scheduler = scheduler
        self._jobs: Dict[str, FabricJobRecord] = {}
        self._failover_events: List[Dict[str, Any]] = []

    def create_job(
        self,
        capability: str,
        assigned_node_id: str,
        request_id: Optional[str] = None,
        priority: WorkloadPriority = WorkloadPriority.NORMAL,
        max_retries: int = 3,
        caller_id: str = "system-user",
        data_classification: DataClassification = DataClassification.INTERNAL,
        required_model: Optional[str] = None,
        allowed_zones: Optional[List[NetworkZone]] = None,
    ) -> FabricJobRecord:
        """Registers a durable job for execution."""
        job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:8].upper()}"

        job = FabricJobRecord(
            job_id=job_id,
            request_id=req_id,
            assigned_node_id=assigned_node_id,
            capability=capability,
            state=JobState.ASSIGNED,
            priority=priority,
            max_retries=max_retries,
            initial_node_id=assigned_node_id,
            data_classification=data_classification,
            required_model=required_model,
            allowed_zones=allowed_zones,
        )
        self._jobs[job_id] = job
        self.scheduler.allocate_job(assigned_node_id, caller_id)
        return job

    def get_job(self, job_id: str) -> Optional[FabricJobRecord]:
        return self._jobs.get(job_id)

    def list_jobs(self, state: Optional[JobState] = None, node_id: Optional[str] = None) -> List[FabricJobRecord]:
        jobs = list(self._jobs.values())
        if state:
            jobs = [j for j in jobs if j.state == state]
        if node_id:
            jobs = [j for j in jobs if j.assigned_node_id == node_id]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def checkpoint_job(self, job_id: str, step_name: str, state_snapshot: Dict[str, Any]) -> FabricJobRecord:
        """Saves intermediate execution progress for checkpoint recovery (Section 34.21)."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found")
        job.add_checkpoint(step_name, state_snapshot)
        return job

    def complete_job(self, job_id: str, result: Dict[str, Any], caller_id: str = "system-user") -> FabricJobRecord:
        """Marks job successfully completed."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found")
        job.state = JobState.COMPLETED
        job.result = result
        job.updated_at = time.time()
        self.scheduler.release_job(job.assigned_node_id, caller_id)
        return job

    def fail_job(self, job_id: str, error_message: str, caller_id: str = "system-user") -> FabricJobRecord:
        """Marks job permanently failed."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found")
        job.state = JobState.FAILED
        job.error_message = error_message
        job.updated_at = time.time()
        self.scheduler.release_job(job.assigned_node_id, caller_id)
        return job

    def handle_node_failure(self, failed_node_id: str, reason: str = "Heartbeat timeout / node crash") -> List[Dict[str, Any]]:
        """Scans for active jobs running on the failed node and initiates automated failover (Section 34.17)."""
        active_states = (JobState.ASSIGNED, JobState.RUNNING, JobState.CHECKPOINTED)
        affected_jobs = [j for j in self._jobs.values() if j.assigned_node_id == failed_node_id and j.state in active_states]
        failover_results = []

        for job in affected_jobs:
            # Release slot on dead node
            self.scheduler.release_job(failed_node_id, "system-user")

            if job.retry_count >= job.max_retries:
                job.state = JobState.FAILED
                job.error_message = f"Exceeded max retries ({job.max_retries}) following failure of node {failed_node_id}"
                failover_results.append({
                    "job_id": job.job_id,
                    "failed": True,
                    "reason": job.error_message,
                })
                continue

            job.state = JobState.FAILOVER_PENDING
            job.retry_count += 1

            # Request new placement from scheduler
            sched_req = WorkloadRequest(
                request_id=f"FAILOVER-{job.request_id}",
                capability=job.capability,
                required_model=getattr(job, "required_model", None),
                data_classification=getattr(job, "data_classification", DataClassification.INTERNAL),
                allowed_zones=getattr(job, "allowed_zones", None),
                priority=WorkloadPriority.CRITICAL,  # Elevate priority for recovered jobs
            )
            decision: SchedulingDecision = self.scheduler.schedule(sched_req)

            if not decision.scheduled or not decision.selected_node_id:
                job.state = JobState.FAILED
                job.error_message = "Failover failed: No replacement node with required capability or resources"
                failover_results.append({
                    "job_id": job.job_id,
                    "failed": True,
                    "reason": job.error_message,
                })
                continue

            replacement_node_id = decision.selected_node_id
            failover_record = {
                "attempt": job.retry_count,
                "failed_node": failed_node_id,
                "replacement_node": replacement_node_id,
                "timestamp": time.time(),
                "reason": reason,
                "last_checkpoint_step": job.checkpoints[-1]["step"] if job.checkpoints else "initial",
            }
            job.failover_history.append(failover_record)
            self._failover_events.append(failover_record)

            # Re-assign and allocate on new node
            job.assigned_node_id = replacement_node_id
            job.state = JobState.RETRYING
            job.updated_at = time.time()
            self.scheduler.allocate_job(replacement_node_id, "system-user")

            # Advance to RUNNING from last checkpoint
            job.state = JobState.RUNNING
            failover_results.append({
                "job_id": job.job_id,
                "recovered": True,
                "previous_node": failed_node_id,
                "replacement_node": replacement_node_id,
                "retry_count": job.retry_count,
                "resumed_from_checkpoint": failover_record["last_checkpoint_step"],
            })

        return failover_results

    def get_failover_history(self) -> List[Dict[str, Any]]:
        return list(self._failover_events)
