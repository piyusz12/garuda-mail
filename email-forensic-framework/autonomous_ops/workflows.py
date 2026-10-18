"""Garuda Phase 35: Module H - Durable Multi-Agent Workflow Orchestration.
Stateful multi-step agent plans with durable checkpoints, step-level deadlines,
and just-in-time policy authorization.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class WorkflowStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RESUMED_FROM_CHECKPOINT = "RESUMED_FROM_CHECKPOINT"


@dataclass
class WorkflowStepState:
    step_id: str
    name: str
    status: str  # PENDING, RUNNING, CHECKPOINTED, COMPLETED, FAILED, AWAITING_APPROVAL
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "status": self.status,
            "requires_approval": self.requires_approval,
            "approved_by": self.approved_by,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }


class WorkflowInstance:
    """Wrapper supporting both attribute and dict-like access for workflows."""
    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def workflow_id(self) -> str:
        return self._data["workflow_id"]

    @property
    def status(self) -> str:
        return self._data["status"]

    def __getitem__(self, item):
        return self._data[item]

    def __setitem__(self, key, value):
        self._data[key] = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self._data["workflow_id"],
            "name": self._data["name"],
            "caller_id": self._data["caller_id"],
            "current_step_index": self._data["current_step_index"],
            "steps": [s.to_dict() for s in self._data["steps"]],
            "checkpoints_count": len(self._data["checkpoints"]),
            "status": self._data["status"],
            "is_sensitive": self._data["is_sensitive"],
        }


class DurableWorkflowEngine:
    """Coordinates resilient, checkpointed multi-step workflows across the fabric."""

    def __init__(self):
        self._workflows: Dict[str, Dict[str, Any]] = {}

    def create_workflow(
        self,
        workflow_name: str,
        caller_id: str = "analyst@garuda.internal",
        is_sensitive: bool = False,
    ) -> WorkflowInstance:
        """Creates a stateful multi-step forensic investigation workflow."""
        wf_id = f"WF-{uuid.uuid4().hex[:8].upper()}"

        steps = [
            WorkflowStepState("STEP-1", "parse_document", "PENDING", {}),
            WorkflowStepState("STEP-2", "extract_evidence", "PENDING", {}),
            WorkflowStepState("STEP-3", "retrieve_rag", "PENDING", {}),
            WorkflowStepState("STEP-4", "generate_draft", "PENDING", {}),
            WorkflowStepState("STEP-5", "validate_output", "PENDING", {}),
            WorkflowStepState("STEP-6", "export_report", "PENDING", {}, requires_approval=is_sensitive),
            WorkflowStepState("STEP-7", "record_audit_result", "PENDING", {}),
        ]

        workflow = {
            "workflow_id": wf_id,
            "name": workflow_name,
            "caller_id": caller_id,
            "current_step_index": 0,
            "steps": steps,
            "checkpoints": [],
            "status": WorkflowStatus.INITIALIZED.value,
            "is_sensitive": is_sensitive,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        self._workflows[wf_id] = workflow
        return WorkflowInstance(workflow)

    def create_forensic_pipeline(
        self,
        workflow_name: str = "Forensic Document Pipeline",
        document_id: str = "DOC-882",
        user_id: str = "analyst@garuda.internal",
    ) -> WorkflowInstance:
        """Helper to create standard forensic pipeline with export approval gate."""
        return self.create_workflow(
            workflow_name=f"{workflow_name} [{document_id}]",
            caller_id=user_id,
            is_sensitive=True,
        )

    def execute_next_step(self, workflow_id: str) -> Dict[str, Any]:
        """Advances the workflow by one step, enforcing policy checks and committing an immutable checkpoint."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        curr_idx = wf["current_step_index"]
        if curr_idx >= len(wf["steps"]):
            wf["status"] = WorkflowStatus.COMPLETED.value
            return {"workflow_id": workflow_id, "status": WorkflowStatus.COMPLETED.value, "message": "Workflow fully completed"}

        step: WorkflowStepState = wf["steps"][curr_idx]

        # Check approval gate (Section 35.10)
        if step.requires_approval and not step.approved_by:
            step.status = "AWAITING_APPROVAL"
            wf["status"] = WorkflowStatus.AWAITING_APPROVAL.value
            return {
                "workflow_id": workflow_id,
                "step_name": step.name,
                "status": "AWAITING_APPROVAL",
                "message": f"Step '{step.name}' requires human authorization prior to execution",
            }

        step.status = "RUNNING"
        step.started_at = time.time()

        # Execute simulated step
        step.output_data = {
            "result": f"Executed step '{step.name}' successfully",
            "timestamp": time.time(),
        }
        step.status = "COMPLETED"
        step.completed_at = time.time()

        # Save checkpoint
        checkpoint = {
            "checkpoint_id": f"CHK-{uuid.uuid4().hex[:6].upper()}",
            "step_index": curr_idx,
            "step_name": step.name,
            "timestamp": time.time(),
        }
        wf["checkpoints"].append(checkpoint)
        wf["current_step_index"] += 1
        wf["updated_at"] = time.time()

        if wf["current_step_index"] >= len(wf["steps"]):
            wf["status"] = WorkflowStatus.COMPLETED.value
        else:
            wf["status"] = WorkflowStatus.IN_PROGRESS.value

        return {
            "workflow_id": workflow_id,
            "step_completed": step.name,
            "next_step_index": wf["current_step_index"],
            "status": wf["status"],
            "checkpoint": checkpoint,
        }

    def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Runs workflow steps until completed or halted at an approval gate."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        last_result = None
        while wf["current_step_index"] < len(wf["steps"]):
            last_result = self.execute_next_step(workflow_id)
            if last_result.get("status") == "AWAITING_APPROVAL":
                break

        return {
            "workflow_id": workflow_id,
            "status": wf["status"],
            "steps_completed": wf["current_step_index"],
            "total_steps": len(wf["steps"]),
            "last_step": last_result,
        }

    def submit_step_approval(self, workflow_id: str, step_name: str, approver: str = "admin@garuda.internal") -> bool:
        """Approves a blocked workflow step."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            return False

        for step in wf["steps"]:
            if step.name == step_name:
                step.approved_by = approver
                step.status = "APPROVED"
                wf["status"] = WorkflowStatus.IN_PROGRESS.value
                return True
        return False

    def resume_from_checkpoint(self, workflow_id: str, checkpoint_index: Optional[int] = None) -> Dict[str, Any]:
        """Recovers an interrupted workflow from its latest valid checkpoint."""
        wf = self._workflows.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        if checkpoint_index is not None:
            target_idx = checkpoint_index
        elif wf.get("checkpoints"):
            latest_cp = wf["checkpoints"][-1]
            target_idx = latest_cp.get("step_index", 0) + 1
        else:
            target_idx = 0

        wf["current_step_index"] = target_idx
        wf["status"] = WorkflowStatus.RESUMED_FROM_CHECKPOINT.value
        return {
            "workflow_id": workflow_id,
            "resumed_from_step_index": target_idx,
            "checkpoint_restored": True,
        }

    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        wf = self._workflows.get(workflow_id)
        if not wf:
            return None
        return WorkflowInstance(wf).to_dict()
