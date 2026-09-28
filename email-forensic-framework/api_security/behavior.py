"""
API Behavioral Baselines and Access Event Logging.
Component 32: Normalizes API access telemetry and defines behavioral profiles per endpoint.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
import time


@dataclass
class APIAccessEvent:
    event_id: str
    endpoint_id: str
    caller_identity: str
    caller_workload_id: str
    client_ip: str
    method: str
    status_code: int
    response_time_ms: float
    auth_header_present: bool = True
    mtls_verified: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "endpoint_id": self.endpoint_id,
            "caller_identity": self.caller_identity,
            "caller_workload_id": self.caller_workload_id,
            "client_ip": self.client_ip,
            "method": self.method,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "auth_header_present": self.auth_header_present,
            "mtls_verified": self.mtls_verified,
            "timestamp": self.timestamp,
        }


@dataclass
class APIBaseline:
    endpoint_id: str
    approved_callers: Set[str] = field(default_factory=set)
    approved_workloads: Set[str] = field(default_factory=set)
    allowed_methods: Set[str] = field(default_factory=lambda: {"GET", "POST"})
    max_normal_rpm: int = 1000

    def check_deviation(self, event: APIAccessEvent) -> List[str]:
        deviations = []
        if self.approved_callers and event.caller_identity not in self.approved_callers:
            deviations.append(f"unauthorized_caller: {event.caller_identity}")
        if self.approved_workloads and event.caller_workload_id not in self.approved_workloads:
            deviations.append(f"unauthorized_calling_workload: {event.caller_workload_id}")
        if event.method not in self.allowed_methods:
            deviations.append(f"unexpected_method: {event.method}")
        return deviations
