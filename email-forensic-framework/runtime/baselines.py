"""
Workload Baseline Management.
Component 44: Manages repository of runtime baselines across workloads, namespaces, and clusters.
"""
from typing import Dict, Optional, List
from runtime.behavior import WorkloadRuntimeBaseline
from runtime.telemetry import RuntimeEvent


class RuntimeBaselineManager:
    """Stores and evaluates runtime baselines for all registered workloads."""

    def __init__(self):
        self._baselines: Dict[str, WorkloadRuntimeBaseline] = {}
        self._seed_default_baselines()

    def _seed_default_baselines(self) -> None:
        """Seed default known baselines for standard workloads (e.g. WORKLOAD-991 MTA-07)."""
        # WORKLOAD-991: Enterprise Mail Transfer Agent
        mta_baseline = WorkloadRuntimeBaseline(
            workload_id="WORKLOAD-991",
            approved_processes={"python", "garuda-mta", "gunicorn", "postfix", "smtpd"},
            approved_outbound_ports={25, 465, 587, 8443, 5432},
            approved_destinations={"10.0.1.10", "10.0.1.20", "10.0.2.5", "smtp.garuda.enterprise"},
            allowed_uids={1000, 1001},
            learning_mode=False,
        )
        self.register_baseline(mta_baseline)

        # WORKLOAD-101: Forensic API Service
        forensic_baseline = WorkloadRuntimeBaseline(
            workload_id="WORKLOAD-101",
            approved_processes={"python", "uvicorn", "garuda-forensic-api"},
            approved_outbound_ports={443, 8443, 5432, 9200},
            approved_destinations={"10.0.2.15", "10.0.2.50", "api.internal.garuda.enterprise"},
            allowed_uids={1000},
            learning_mode=False,
        )
        self.register_baseline(forensic_baseline)

    def register_baseline(self, baseline: WorkloadRuntimeBaseline) -> None:
        self._baselines[baseline.workload_id] = baseline

    def get_baseline(self, workload_id: str) -> Optional[WorkloadRuntimeBaseline]:
        return self._baselines.get(workload_id)

    def list_baselines(self) -> List[WorkloadRuntimeBaseline]:
        return list(self._baselines.values())

    def evaluate_event(self, event: RuntimeEvent) -> List[str]:
        """Check event against workload's baseline. Returns deviations."""
        baseline = self.get_baseline(event.workload_id)
        if not baseline:
            # If no baseline exists, return unbaselined workload warning
            return [f"unbaselined_workload: {event.workload_id}"]
        return baseline.check_deviation(event)
