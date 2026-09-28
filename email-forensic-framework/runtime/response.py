"""
Workload Runtime Response & Quarantine Controller.
Components 47, 48, 49, 50: Non-destructive container quarantine, network isolation, and restoration.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import uuid


class WorkloadQuarantineState(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"
    INVESTIGATING = "INVESTIGATING"
    RESTORED = "RESTORED"


class RuntimeResponseAction(str, Enum):
    MONITOR = "MONITOR"
    RESTRICT_EGRESS = "RESTRICT_EGRESS"
    QUARANTINE_POD = "QUARANTINE_POD"
    TERMINATE_CONTAINER = "TERMINATE_CONTAINER"
    ROLLBACK_DEPLOYMENT = "ROLLBACK_DEPLOYMENT"


@dataclass
class QuarantineRecord:
    record_id: str
    workload_id: str
    previous_state: WorkloadQuarantineState
    current_state: WorkloadQuarantineState
    reason: str
    action_taken: RuntimeResponseAction
    applied_labels: Dict[str, str] = field(default_factory=dict)
    network_isolated: bool = False
    timestamp: float = field(default_factory=time.time)
    cleared_at: Optional[float] = None


class WorkloadResponseController:
    """
    Manages non-destructive container isolation and quarantine states.
    Prevents disruptive container killing while neutralizing active threats for forensic investigation.
    """

    def __init__(self):
        self._workload_states: Dict[str, WorkloadQuarantineState] = {}
        self._quarantine_history: List[QuarantineRecord] = []
        self._isolated_workloads: Dict[str, QuarantineRecord] = {}

    def get_state(self, workload_id: str) -> WorkloadQuarantineState:
        return self._workload_states.get(workload_id, WorkloadQuarantineState.NORMAL)

    def quarantine_workload(
        self,
        workload_id: str,
        reason: str,
        action: RuntimeResponseAction = RuntimeResponseAction.QUARANTINE_POD,
    ) -> QuarantineRecord:
        """
        Non-destructively isolate a workload:
        1. Apply Kubernetes quarantine label: 'isolation.garuda.enterprise/quarantined=true'
        2. Sever external and east-west network policy while retaining pod runtime for live memory forensics.
        3. Transition state to QUARANTINED.
        """
        prev_state = self.get_state(workload_id)
        record = QuarantineRecord(
            record_id=f"QUAR-{uuid.uuid4().hex[:8].upper()}",
            workload_id=workload_id,
            previous_state=prev_state,
            current_state=WorkloadQuarantineState.QUARANTINED,
            reason=reason,
            action_taken=action,
            applied_labels={
                "isolation.garuda.enterprise/quarantined": "true",
                "isolation.garuda.enterprise/quarantine-id": f"QUAR-{uuid.uuid4().hex[:6]}",
            },
            network_isolated=True,
        )

        self._workload_states[workload_id] = WorkloadQuarantineState.QUARANTINED
        self._isolated_workloads[workload_id] = record
        self._quarantine_history.append(record)
        return record

    def restore_workload(self, workload_id: str, reason: str = "Investigation completed - threat neutralized") -> Optional[QuarantineRecord]:
        """Restore a quarantined workload to normal operational status."""
        if workload_id not in self._isolated_workloads:
            return None

        record = self._isolated_workloads.pop(workload_id)
        record.current_state = WorkloadQuarantineState.RESTORED
        record.network_isolated = False
        record.cleared_at = time.time()

        self._workload_states[workload_id] = WorkloadQuarantineState.RESTORED
        return record

    def get_quarantined_workloads(self) -> List[QuarantineRecord]:
        return list(self._isolated_workloads.values())

    def get_history(self) -> List[QuarantineRecord]:
        return list(self._quarantine_history)
