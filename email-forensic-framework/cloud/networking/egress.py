"""
Workload Egress Security and Anomaly Detection.
Component 30: Monitors outbound communication, detecting unauthorized external endpoints and data exfiltration.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
import time


@dataclass
class EgressEvent:
    event_id: str
    workload_id: str
    destination_ip: str
    destination_port: int
    destination_domain: Optional[str] = None
    protocol: str = "TCP"
    bytes_sent: int = 1024
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "workload_id": self.workload_id,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "destination_domain": self.destination_domain,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "timestamp": self.timestamp,
        }


class EgressAnomalyDetector:
    """Detects unexpected outbound traffic and anomalous egress from workloads."""

    def __init__(self):
        # workload_id -> Set of approved destination IPs/domains/CIDRs
        self._approved_egress: Dict[str, Set[str]] = {}
        self._load_defaults()

    def _load_defaults(self):
        # Default approved egress for MTA-07
        self._approved_egress["WORKLOAD-991"] = {
            "10.200.1.7",
            "mta-relay.enterprise.org",
            "smtp.relay.service",
            "142.250.190.27",  # Known mail peer
        }

    def set_approved_egress(self, workload_id: str, destinations: Set[str]) -> None:
        self._approved_egress[workload_id] = destinations

    def is_egress_authorized(self, event: EgressEvent) -> bool:
        approved = self._approved_egress.get(event.workload_id)
        if not approved:
            # If no policy defined, default egress is flagged for inspection
            return False

        if event.destination_domain and event.destination_domain in approved:
            return True
        if event.destination_ip in approved:
            return True

        return False

    def evaluate_egress(self, event: EgressEvent) -> Optional[Dict[str, Any]]:
        if not self.is_egress_authorized(event):
            return {
                "event_id": event.event_id,
                "workload_id": event.workload_id,
                "violation": "UNEXPECTED_EXTERNAL_EGRESS",
                "destination": event.destination_domain or event.destination_ip,
                "port": event.destination_port,
                "severity": "HIGH",
                "recommendation": f"Enforce NetworkPolicy restricting {event.workload_id} egress to approved destinations only.",
            }
        return None
