"""
Workload Runtime Behavior & Baselines.
Component 24 & 44: Profiles approved runtime behaviors (executables, ports, destinations, uids).
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from runtime.telemetry import RuntimeEvent, RuntimeEventType


@dataclass
class WorkloadRuntimeBaseline:
    workload_id: str
    approved_processes: Set[str] = field(default_factory=set)
    approved_outbound_ports: Set[int] = field(default_factory=set)
    approved_destinations: Set[str] = field(default_factory=set)
    allowed_uids: Set[int] = field(default_factory=lambda: {1000, 1001})
    learning_mode: bool = False

    def learn_event(self, event: RuntimeEvent) -> None:
        """Dynamically expand baseline if in learning mode."""
        if not self.learning_mode:
            return
        if event.process_name:
            self.approved_processes.add(event.process_name)
        if event.destination_port:
            self.approved_outbound_ports.add(event.destination_port)
        if event.destination_ip:
            self.approved_destinations.add(event.destination_ip)
        self.allowed_uids.add(event.uid)

    def check_deviation(self, event: RuntimeEvent) -> List[str]:
        """
        Check if an incoming runtime event deviates from approved baseline.
        Returns list of deviation descriptions.
        """
        if self.learning_mode:
            return []

        deviations = []
        if event.process_name and self.approved_processes and event.process_name not in self.approved_processes:
            deviations.append(f"unapproved_process: {event.process_name}")

        if (
            event.destination_port
            and self.approved_outbound_ports
            and event.destination_port not in self.approved_outbound_ports
        ):
            deviations.append(f"unapproved_outbound_port: {event.destination_port}")

        if (
            event.destination_ip
            and self.approved_destinations
            and event.destination_ip not in self.approved_destinations
        ):
            deviations.append(f"unapproved_destination: {event.destination_ip}")

        if event.uid not in self.allowed_uids:
            deviations.append(f"unexpected_uid: {event.uid} (allowed: {sorted(list(self.allowed_uids))})")

        return deviations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "approved_processes": sorted(list(self.approved_processes)),
            "approved_outbound_ports": sorted(list(self.approved_outbound_ports)),
            "approved_destinations": sorted(list(self.approved_destinations)),
            "allowed_uids": sorted(list(self.allowed_uids)),
            "learning_mode": self.learning_mode,
        }
