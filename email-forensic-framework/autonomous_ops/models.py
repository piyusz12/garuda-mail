"""Garuda Phase 35: Autonomous AI Orchestration, Self-Optimization & Self-Healing.
Core domain models, dataclasses, enums, and operational contracts.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class AutonomyMode(str, Enum):
    OBSERVE = "OBSERVE"
    RECOMMEND_AND_APPROVE = "RECOMMEND_AND_APPROVE"
    BOUNDED_AUTOMATION = "BOUNDED_AUTOMATION"


class ActionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionExecutionStatus(str, Enum):
    PLANNED = "PLANNED"
    EVALUATED = "EVALUATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentLifecycleStatus(str, Enum):
    DETECTED = "DETECTED"
    CLASSIFIED = "CLASSIFIED"
    RISK_ASSESSED = "RISK_ASSESSED"
    CONTAINMENT = "CONTAINMENT"
    RECOVERY = "RECOVERY"
    VERIFICATION = "VERIFICATION"
    RESOLVED = "RESOLVED"


class AnomalyType(str, Enum):
    LATENCY_SPIKE = "LATENCY_SPIKE"
    VRAM_PRESSURE = "VRAM_PRESSURE"
    REPEATED_MODEL_CRASH = "REPEATED_MODEL_CRASH"
    QUEUE_OVERLOAD = "QUEUE_OVERLOAD"
    AUTH_SPIKE = "AUTH_SPIKE"
    WORKER_IDLE_BURDEN = "WORKER_IDLE_BURDEN"


@dataclass
class CorrelatedSpan:
    span_id: str
    name: str
    start_time: float
    end_time: float
    duration_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration_ms, 2),
            "metadata": self.metadata,
        }


@dataclass
class CorrelatedTrace:
    trace_id: str
    request_id: str
    user_id: str
    entry_point: str
    model_selected: Optional[str]
    node_selected: Optional[str]
    spans: List[CorrelatedSpan] = field(default_factory=list)
    total_duration_ms: float = 0.0
    success: bool = True
    created_at: float = field(default_factory=time.time)

    def add_span(self, name: str, start_time: float, end_time: float, metadata: Optional[Dict[str, Any]] = None) -> CorrelatedSpan:
        dur = max(0.0, (end_time - start_time) * 1000.0)
        span = CorrelatedSpan(
            span_id=f"SPAN-{uuid.uuid4().hex[:6].upper()}",
            name=name,
            start_time=start_time,
            end_time=end_time,
            duration_ms=dur,
            metadata=metadata or {},
        )
        self.spans.append(span)
        self.total_duration_ms += dur
        return span

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "entry_point": self.entry_point,
            "model_selected": self.model_selected,
            "node_selected": self.node_selected,
            "spans_count": len(self.spans),
            "spans": [s.to_dict() for s in self.spans],
            "total_duration_ms": round(self.total_duration_ms, 2),
            "success": self.success,
            "created_at": self.created_at,
        }


@dataclass
class ActionPlan:
    action_id: str
    action_type: str
    target_resource: str
    reason: str
    risk_level: ActionRiskLevel
    reversible: bool
    approval_required: bool
    expected_effect: str
    rollback_plan: str
    policy_decision: str = "ALLOW"
    status: ActionExecutionStatus = ActionExecutionStatus.PLANNED
    created_at: float = field(default_factory=time.time)
    executed_at: Optional[float] = None
    approved_by: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_resource": self.target_resource,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "reversible": self.reversible,
            "approval_required": self.approval_required,
            "expected_effect": self.expected_effect,
            "rollback_plan": self.rollback_plan,
            "policy_decision": self.policy_decision,
            "status": self.status.value,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
            "approved_by": self.approved_by,
            "result": self.result,
            "error": self.error,
            "parameters": self.parameters,
        }


@dataclass
class OperationalIncident:
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentLifecycleStatus
    target_resource: str
    detection_source: str
    description: str
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None

    def add_timeline_event(self, stage: IncidentLifecycleStatus, detail: str) -> None:
        self.timeline.append({
            "stage": stage.value,
            "detail": detail,
            "timestamp": time.time(),
        })
        self.status = stage

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "target_resource": self.target_resource,
            "detection_source": self.detection_source,
            "description": self.description,
            "timeline": self.timeline,
            "containment_actions": self.containment_actions,
            "recovery_actions": self.recovery_actions,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
        }


@dataclass
class OptimizationExperiment:
    experiment_id: str
    title: str
    hypothesis: str
    baseline_metrics: Dict[str, float]
    proposed_metrics: Dict[str, float]
    test_workload_size: int
    improvement_pct: float
    accepted: bool
    created_at: float = field(default_factory=time.time)
    rollback_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "baseline_metrics": self.baseline_metrics,
            "proposed_metrics": self.proposed_metrics,
            "test_workload_size": self.test_workload_size,
            "improvement_pct": round(self.improvement_pct, 1),
            "accepted": self.accepted,
            "created_at": self.created_at,
            "rollback_reason": self.rollback_reason,
        }
