"""Garuda Enterprise AI Security - Workflow & Pipeline Security.
Phase 30 Section 30.38, 30.39, 30.40, 30.41: Multi-stage workflow governance,
chain-of-custody tracking, and AI-to-API / AI-to-Database access validation.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid

from data_security.inventory.normalization import ClassificationLevel


class WorkflowStageType(str, Enum):
    INPUT = "INPUT"
    CLASSIFIER = "CLASSIFIER"
    RETRIEVER = "RETRIEVER"
    RERANKER = "RERANKER"
    LLM = "LLM"
    TOOL = "TOOL"
    DATABASE = "DATABASE"
    API = "API"
    POSTPROCESSOR = "POSTPROCESSOR"
    OUTPUT = "OUTPUT"


@dataclass
class WorkflowStageRecord:
    stage_id: str
    stage_type: WorkflowStageType
    name: str
    component_ref: str
    allowed_classifications: List[ClassificationLevel] = field(default_factory=lambda: [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL])
    requires_auth: bool = True
    timeout_seconds: float = 30.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "stage_type": self.stage_type.value,
            "name": self.name,
            "component_ref": self.component_ref,
            "allowed_classifications": [c.value for c in self.allowed_classifications],
            "requires_auth": self.requires_auth,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class WorkflowExecutionEvaluation:
    is_allowed: bool
    blocked_stage_id: Optional[str]
    reason: str
    data_classification: ClassificationLevel
    trace: List[Dict[str, Any]] = field(default_factory=list)


class AIWorkflowChain:
    """Manages an ordered multi-stage AI workflow pipeline."""

    def __init__(self, workflow_id: str, name: str, agent_id: str):
        self.workflow_id = workflow_id
        self.name = name
        self.agent_id = agent_id
        self.stages: List[WorkflowStageRecord] = []

    def add_stage(self, stage: WorkflowStageRecord):
        self.stages.append(stage)

    def validate_execution(
        self,
        input_classification: ClassificationLevel,
        target_api_endpoints: Optional[List[str]] = None,
        target_db_tables: Optional[List[str]] = None,
    ) -> WorkflowExecutionEvaluation:
        """Validates that all stages in the workflow can process the data classification
        and adhere to AI-to-API and AI-to-Database policies."""
        trace = []
        for stage in self.stages:
            stage_entry = {
                "stage_id": stage.stage_id,
                "stage_type": stage.stage_type.value,
                "component": stage.component_ref,
                "timestamp": time.time(),
            }
            # Check data classification clearance at this stage
            if input_classification not in stage.allowed_classifications:
                trace.append({**stage_entry, "status": "DENIED", "reason": f"Classification {input_classification.value} exceeds stage clearance"})
                return WorkflowExecutionEvaluation(
                    is_allowed=False,
                    blocked_stage_id=stage.stage_id,
                    reason=f"Stage '{stage.name}' cannot handle {input_classification.value} data",
                    data_classification=input_classification,
                    trace=trace,
                )

            # AI-to-Database checks (Section 30.41)
            if stage.stage_type == WorkflowStageType.DATABASE and target_db_tables:
                for tbl in target_db_tables:
                    if "restricted" in tbl.lower() or "customer_pii" in tbl.lower():
                        if input_classification != ClassificationLevel.RESTRICTED:
                            trace.append({**stage_entry, "status": "DENIED", "reason": f"Access to sensitive table {tbl} disallowed for workflow {self.workflow_id}"})
                            return WorkflowExecutionEvaluation(
                                is_allowed=False,
                                blocked_stage_id=stage.stage_id,
                                reason=f"AI-to-Database policy blocked access to sensitive table '{tbl}'",
                                data_classification=input_classification,
                                trace=trace,
                            )

            # AI-to-API checks (Section 30.40)
            if stage.stage_type == WorkflowStageType.API and target_api_endpoints:
                for ep in target_api_endpoints:
                    if ep.startswith("https://api.external.") or ep.startswith("http://"):
                        if input_classification in (ClassificationLevel.RESTRICTED, ClassificationLevel.CONFIDENTIAL):
                            trace.append({**stage_entry, "status": "DENIED", "reason": f"External API egress prohibited for {input_classification.value} data"})
                            return WorkflowExecutionEvaluation(
                                is_allowed=False,
                                blocked_stage_id=stage.stage_id,
                                reason=f"AI-to-API policy severed external endpoint '{ep}' for sensitive payload",
                                data_classification=input_classification,
                                trace=trace,
                            )

            trace.append({**stage_entry, "status": "ALLOWED"})

        return WorkflowExecutionEvaluation(
            is_allowed=True,
            blocked_stage_id=None,
            reason="All workflow stages cleared security authorization",
            data_classification=input_classification,
            trace=trace,
        )


class AIWorkflowManager:
    """Registry and manager for AI workflow chains."""

    def __init__(self):
        self._workflows: Dict[str, AIWorkflowChain] = {}
        self.register_default_workflow()

    def register_default_workflow(self):
        wf = AIWorkflowChain("WF-CUSTOMER-SUPPORT", "Customer Support RAG & Action Workflow", "AGENT-41")
        wf.add_stage(WorkflowStageRecord("STG-01", WorkflowStageType.INPUT, "Inbound Sanitizer", "input-sanitizer", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL, ClassificationLevel.RESTRICTED]))
        wf.add_stage(WorkflowStageRecord("STG-02", WorkflowStageType.CLASSIFIER, "Intent Classifier", "intent-classifier-v1", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL, ClassificationLevel.RESTRICTED]))
        wf.add_stage(WorkflowStageRecord("STG-03", WorkflowStageType.RETRIEVER, "Vector Retriever", "vdb-customer-kb", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL]))
        wf.add_stage(WorkflowStageRecord("STG-04", WorkflowStageType.LLM, "Core Inference", "MODEL-781", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL]))
        wf.add_stage(WorkflowStageRecord("STG-05", WorkflowStageType.DATABASE, "Action Tool", "database_query", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL]))
        wf.add_stage(WorkflowStageRecord("STG-06", WorkflowStageType.POSTPROCESSOR, "DLP & Output Guardrail", "output-guardrail", [ClassificationLevel.PUBLIC, ClassificationLevel.INTERNAL, ClassificationLevel.CONFIDENTIAL, ClassificationLevel.RESTRICTED]))
        self._workflows[wf.workflow_id] = wf

    def register_workflow(self, workflow: AIWorkflowChain):
        self._workflows[workflow.workflow_id] = workflow

    def get_workflow(self, workflow_id: str) -> Optional[AIWorkflowChain]:
        return self._workflows.get(workflow_id)

    def list_workflows(self) -> List[AIWorkflowChain]:
        return list(self._workflows.values())
