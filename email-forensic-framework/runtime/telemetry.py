"""
Container and Workload Runtime Telemetry.
Component 23: Ingests process execution, socket connection, and file modification events.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class RuntimeEventType(str, Enum):
    PROCESS_SPAWNED = "PROCESS_SPAWNED"
    SOCKET_CONNECTED = "SOCKET_CONNECTED"
    FILE_MODIFIED = "FILE_MODIFIED"
    CAPABILITY_ACQUIRED = "CAPABILITY_ACQUIRED"
    SUSPICIOUS_SYSCALL = "SUSPICIOUS_SYSCALL"


@dataclass
class RuntimeEvent:
    event_id: str
    workload_id: str
    container_id: str
    event_type: RuntimeEventType
    process_name: Optional[str] = None
    cmdline: Optional[str] = None
    parent_process: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    file_path: Optional[str] = None
    uid: int = 1000
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "workload_id": self.workload_id,
            "container_id": self.container_id,
            "event_type": self.event_type.value if isinstance(self.event_type, RuntimeEventType) else self.event_type,
            "process_name": self.process_name,
            "cmdline": self.cmdline,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "file_path": self.file_path,
            "uid": self.uid,
            "timestamp": self.timestamp,
        }
