"""Garuda Distributed Sovereign AI Fabric & Multi-Node Orchestration.
Phase 34: Data structures, enums, models, and contracts for distributed compute fabric.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class NodeStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    RECOVERING = "RECOVERING"
    QUARANTINED = "QUARANTINED"


class NodeTrust(str, Enum):
    TRUSTED = "TRUSTED"
    LIMITED = "LIMITED"
    UNTRUSTED = "UNTRUSTED"
    QUARANTINED = "QUARANTINED"


class NodeRole(str, Enum):
    WORKER_GPU = "WORKER_GPU"
    WORKER_CPU = "WORKER_CPU"
    STORAGE_RAG = "STORAGE_RAG"
    GATEWAY = "GATEWAY"
    CONTROL_PLANE = "CONTROL_PLANE"


class NetworkZone(str, Enum):
    RESTRICTED_AI = "RESTRICTED_AI"
    INTERNAL_AI = "INTERNAL_AI"
    GENERAL_AI = "GENERAL_AI"
    STORAGE_NET = "STORAGE_NET"
    MANAGEMENT_NET = "MANAGEMENT_NET"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"


class WorkloadPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"
    BACKGROUND = "BACKGROUND"


class ModelLifecycleStatus(str, Enum):
    REGISTERED = "REGISTERED"
    DOWNLOADING = "DOWNLOADING"
    LOADING = "LOADING"
    READY = "READY"
    BUSY = "BUSY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNLOADING = "UNLOADING"
    DEPRECATED = "DEPRECATED"


class JobState(str, Enum):
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    RUNNING = "RUNNING"
    CHECKPOINTED = "CHECKPOINTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    FAILOVER_PENDING = "FAILOVER_PENDING"
    RETRYING = "RETRYING"


class EnrollmentStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class NodeIdentity:
    node_id: str
    public_key: str
    private_key_hash: str
    certificate_pem: str
    fingerprint: str
    valid_until: float = field(default_factory=lambda: time.time() + (365 * 86400))

    def is_valid(self) -> bool:
        return time.time() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "valid_until": self.valid_until,
            "is_valid": self.is_valid(),
        }


@dataclass
class FabricNodeRecord:
    node_id: str
    hostname: str
    ip_address: str
    status: NodeStatus
    role: NodeRole
    trust_level: NodeTrust
    network_zone: NetworkZone
    cpu_cores: int
    cpu_usage_pct: float
    ram_total_gb: float
    ram_used_gb: float
    gpu_name: str
    vram_total_gb: float
    vram_used_gb: float
    models_loaded: Dict[str, ModelLifecycleStatus]
    capabilities: List[str]
    software_version: str
    api_version: str = "1.0.0"
    active_jobs: int = 0
    temperature_c: float = 48.0
    disk_used_pct: float = 35.0
    last_seen: float = field(default_factory=time.time)
    security_state: str = "COMPLIANT"
    enrolled_at: float = field(default_factory=time.time)

    @property
    def free_vram_gb(self) -> float:
        return max(0.0, round(self.vram_total_gb - self.vram_used_gb, 2))

    @property
    def free_ram_gb(self) -> float:
        return max(0.0, round(self.ram_total_gb - self.ram_used_gb, 2))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "role": self.role.value if hasattr(self.role, 'value') else str(self.role),
            "trust_level": self.trust_level.value if hasattr(self.trust_level, 'value') else str(self.trust_level),
            "network_zone": self.network_zone.value if hasattr(self.network_zone, 'value') else str(self.network_zone),
            "cpu_cores": self.cpu_cores,
            "cpu_usage_pct": self.cpu_usage_pct,
            "ram_total_gb": self.ram_total_gb,
            "ram_used_gb": self.ram_used_gb,
            "free_ram_gb": self.free_ram_gb,
            "gpu_name": self.gpu_name,
            "vram_total_gb": self.vram_total_gb,
            "vram_used_gb": self.vram_used_gb,
            "free_vram_gb": self.free_vram_gb,
            "models_loaded": {k: v.value if hasattr(v, 'value') else str(v) for k, v in self.models_loaded.items()},
            "capabilities": self.capabilities,
            "software_version": self.software_version,
            "api_version": self.api_version,
            "active_jobs": self.active_jobs,
            "temperature_c": self.temperature_c,
            "disk_used_pct": self.disk_used_pct,
            "last_seen": self.last_seen,
            "security_state": self.security_state,
            "enrolled_at": self.enrolled_at,
        }


@dataclass
class EnrollmentRequest:
    request_id: str
    hostname: str
    ip_address: str
    role: NodeRole
    advertised_gpu: str
    advertised_vram_gb: float
    advertised_ram_gb: float
    advertised_capabilities: List[str]
    public_key: str
    requested_zone: NetworkZone
    requested_at: float = field(default_factory=time.time)
    status: EnrollmentStatus = EnrollmentStatus.PENDING_APPROVAL
    decision_reason: Optional[str] = None
    assigned_node_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "role": self.role.value,
            "advertised_gpu": self.advertised_gpu,
            "advertised_vram_gb": self.advertised_vram_gb,
            "advertised_ram_gb": self.advertised_ram_gb,
            "advertised_capabilities": self.advertised_capabilities,
            "public_key": self.public_key,
            "requested_zone": self.requested_zone.value,
            "requested_at": self.requested_at,
            "status": self.status.value,
            "decision_reason": self.decision_reason,
            "assigned_node_id": self.assigned_node_id,
        }


@dataclass
class NodeHeartbeatPayload:
    node_id: str
    status: NodeStatus
    cpu_usage_pct: float
    ram_used_gb: float
    ram_total_gb: float
    gpu_name: str
    vram_used_gb: float
    vram_total_gb: float
    active_jobs: int
    temperature_c: float = 48.0
    disk_used_pct: float = 35.0
    models_state: Dict[str, ModelLifecycleStatus] = field(default_factory=dict)
    capabilities: Optional[List[str]] = None
    software_version: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "status": self.status.value,
            "cpu_usage_pct": self.cpu_usage_pct,
            "ram_used_gb": self.ram_used_gb,
            "ram_total_gb": self.ram_total_gb,
            "gpu_name": self.gpu_name,
            "vram_used_gb": self.vram_used_gb,
            "vram_total_gb": self.vram_total_gb,
            "active_jobs": self.active_jobs,
            "temperature_c": self.temperature_c,
            "disk_used_pct": self.disk_used_pct,
            "models_state": {k: v.value if hasattr(v, 'value') else str(v) for k, v in self.models_state.items()},
            "capabilities": self.capabilities,
            "software_version": self.software_version,
            "timestamp": self.timestamp,
        }


@dataclass
class WorkloadRequest:
    request_id: str
    capability: str
    required_model: Optional[str] = None
    min_vram_gb: float = 0.0
    min_ram_gb: float = 0.0
    data_classification: DataClassification = DataClassification.INTERNAL
    allowed_zones: Optional[List[NetworkZone]] = None
    priority: WorkloadPriority = WorkloadPriority.NORMAL
    max_latency_ms: float = 5000.0
    idempotent_key: Optional[str] = None
    caller_id: str = "system-user"
    caller_role: str = "user"
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "capability": self.capability,
            "required_model": self.required_model,
            "min_vram_gb": self.min_vram_gb,
            "min_ram_gb": self.min_ram_gb,
            "data_classification": self.data_classification.value,
            "allowed_zones": [z.value for z in self.allowed_zones] if self.allowed_zones else None,
            "priority": self.priority.value,
            "max_latency_ms": self.max_latency_ms,
            "idempotent_key": self.idempotent_key,
            "caller_id": self.caller_id,
            "caller_role": self.caller_role,
            "created_at": self.created_at,
        }


@dataclass
class CandidateScore:
    node_id: str
    score: float
    policy_compat_score: float
    trust_score: float
    resource_score: float
    locality_score: float
    queue_penalty: float
    network_cost: float
    reasons: List[str]
    is_eligible: bool
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "score": round(self.score, 2),
            "policy_compat_score": self.policy_compat_score,
            "trust_score": self.trust_score,
            "resource_score": round(self.resource_score, 2),
            "locality_score": self.locality_score,
            "queue_penalty": self.queue_penalty,
            "network_cost": self.network_cost,
            "reasons": self.reasons,
            "is_eligible": self.is_eligible,
            "rejection_reason": self.rejection_reason,
        }


@dataclass
class SchedulingDecision:
    request_id: str
    selected_node_id: Optional[str]
    selected_node: Optional[Dict[str, Any]]
    explanation: str
    candidate_scores: List[CandidateScore]
    rejected_reasons: Dict[str, str]
    scheduled: bool
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "selected_node_id": self.selected_node_id,
            "selected_node": self.selected_node,
            "explanation": self.explanation,
            "candidate_scores": [c.to_dict() for c in self.candidate_scores],
            "rejected_reasons": self.rejected_reasons,
            "scheduled": self.scheduled,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class FabricJobRecord:
    job_id: str
    request_id: str
    assigned_node_id: str
    capability: str
    state: JobState
    priority: WorkloadPriority
    retry_count: int = 0
    max_retries: int = 3
    checkpoints: List[Dict[str, Any]] = field(default_factory=list)
    initial_node_id: Optional[str] = None
    failover_history: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    data_classification: DataClassification = DataClassification.INTERNAL
    required_model: Optional[str] = None
    allowed_zones: Optional[List[NetworkZone]] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def add_checkpoint(self, step_name: str, state_snapshot: Dict[str, Any]) -> None:
        self.checkpoints.append({
            "step": step_name,
            "snapshot": state_snapshot,
            "timestamp": time.time(),
        })
        self.state = JobState.CHECKPOINTED
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "request_id": self.request_id,
            "assigned_node_id": self.assigned_node_id,
            "capability": self.capability,
            "state": self.state.value if hasattr(self.state, 'value') else str(self.state),
            "priority": self.priority.value if hasattr(self.priority, 'value') else str(self.priority),
            "data_classification": self.data_classification.value if hasattr(self.data_classification, 'value') else str(self.data_classification),
            "required_model": self.required_model,
            "allowed_zones": [z.value if hasattr(z, 'value') else str(z) for z in self.allowed_zones] if self.allowed_zones else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "checkpoints_count": len(self.checkpoints),
            "checkpoints": self.checkpoints,
            "initial_node_id": self.initial_node_id,
            "failover_history": self.failover_history,
            "error_message": self.error_message,
            "result": self.result,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class SecureInterNodeEnvelope:
    envelope_id: str
    request_id: str
    source_node_id: str
    target_node_id: str
    network_zone: NetworkZone
    job_id: str
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    signature: str = ""
    auth_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "request_id": self.request_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "network_zone": self.network_zone.value,
            "job_id": self.job_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "auth_context": self.auth_context,
        }


@dataclass
class DistributedAuditEvent:
    event_id: str
    timestamp: float
    user_id: str
    request_id: str
    action: str
    policy_decision: str
    selected_node: str
    target_model: str
    data_classification: str
    data_zone: str
    failover_occurred: bool
    initial_node: Optional[str]
    replacement_node: Optional[str]
    latency_ms: float
    status: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "action": self.action,
            "policy_decision": self.policy_decision,
            "selected_node": self.selected_node,
            "target_model": self.target_model,
            "data_classification": self.data_classification,
            "data_zone": self.data_zone,
            "failover_occurred": self.failover_occurred,
            "initial_node": self.initial_node,
            "replacement_node": self.replacement_node,
            "latency_ms": round(self.latency_ms, 2),
            "status": self.status,
            "details": self.details,
        }
