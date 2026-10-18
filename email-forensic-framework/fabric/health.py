"""Garuda Distributed Sovereign AI Fabric - Node Health Manager & Failure Detector.
Phase 34 Sections 34.5 & 34.16:
Periodic heartbeats, GPU/VRAM telemetry, health state transitions,
OOM detection, and heartbeat expiration detection.
"""
from typing import Dict, List, Optional, Any, Callable
import time
import hashlib
import hmac

from fabric.models import (
    FabricNodeRecord,
    NodeHeartbeatPayload,
    NodeStatus,
    NodeTrust,
    ModelLifecycleStatus,
)
from fabric.node_registry import NodeRegistry


class NodeHealthManager:
    """Monitors heartbeat streams, assesses node vitals, and triggers state transitions."""

    def __init__(
        self,
        registry: NodeRegistry,
        degraded_threshold_sec: float = 15.0,
        unavailable_threshold_sec: float = 30.0,
    ):
        self.registry = registry
        self.degraded_threshold_sec = degraded_threshold_sec
        self.unavailable_threshold_sec = unavailable_threshold_sec
        self._listeners: List[Callable[[str, NodeStatus, str], None]] = []

    def subscribe_failure_event(self, callback: Callable[[str, NodeStatus, str], None]) -> None:
        """Subscribes to node status change and failure detection events."""
        self._listeners.append(callback)

    def _notify(self, node_id: str, new_status: NodeStatus, reason: str) -> None:
        for listener in self._listeners:
            try:
                listener(node_id, new_status, reason)
            except Exception:
                pass

    def process_heartbeat(self, payload: NodeHeartbeatPayload) -> FabricNodeRecord:
        """Processes an incoming signed heartbeat from a worker node."""
        node = self.registry.get_node(payload.node_id)
        if not node:
            raise ValueError(f"Unknown node '{payload.node_id}' in heartbeat")

        # Quarantined nodes remain quarantined unless unquarantined by admin
        if node.status == NodeStatus.QUARANTINED or node.trust_level == NodeTrust.QUARANTINED:
            node.last_seen = time.time()
            return node

        now = time.time()
        node.last_seen = now
        node.cpu_usage_pct = payload.cpu_usage_pct
        node.ram_used_gb = payload.ram_used_gb
        node.ram_total_gb = payload.ram_total_gb
        node.vram_used_gb = payload.vram_used_gb
        node.vram_total_gb = payload.vram_total_gb
        node.active_jobs = payload.active_jobs
        node.temperature_c = payload.temperature_c
        node.disk_used_pct = payload.disk_used_pct

        if payload.models_state:
            node.models_loaded.update(payload.models_state)
        if payload.capabilities:
            node.capabilities = payload.capabilities
        if payload.software_version:
            node.software_version = payload.software_version

        # Out-Of-Memory / Overload Detection (Section 34.16)
        if node.vram_total_gb > 0 and (node.vram_used_gb >= node.vram_total_gb):
            old_status = node.status
            node.status = NodeStatus.DEGRADED
            node.security_state = "WARNING: GPU VRAM Saturation (Potential OOM)"
            if old_status != NodeStatus.DEGRADED:
                self._notify(node.node_id, NodeStatus.DEGRADED, "GPU VRAM Saturation")
            return node

        # If recovering from unavailable / degraded
        if node.status in (NodeStatus.UNAVAILABLE, NodeStatus.DEGRADED):
            node.status = NodeStatus.RECOVERING
            self._notify(node.node_id, NodeStatus.RECOVERING, "Fresh heartbeat received after outage")
            node.status = NodeStatus.HEALTHY
            node.security_state = "HEALTHY"
        else:
            node.status = payload.status or NodeStatus.HEALTHY
            node.security_state = "HEALTHY"

        return node

    def scan_for_failures(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Scans all nodes for missed heartbeats and advances state machine:
        HEALTHY -> DEGRADED -> UNAVAILABLE
        """
        now = current_time or time.time()
        events = []

        for node in self.registry.list_nodes():
            if node.status == NodeStatus.QUARANTINED:
                continue

            elapsed = now - node.last_seen

            if elapsed >= self.unavailable_threshold_sec and node.status != NodeStatus.UNAVAILABLE:
                old_status = node.status
                node.status = NodeStatus.UNAVAILABLE
                reason = f"Heartbeat missed for {round(elapsed, 1)}s (exceeded {self.unavailable_threshold_sec}s threshold)"
                node.security_state = f"NODE_CRASH: {reason}"
                events.append({
                    "node_id": node.node_id,
                    "previous_status": old_status.value,
                    "new_status": NodeStatus.UNAVAILABLE.value,
                    "reason": reason,
                    "elapsed_sec": round(elapsed, 1),
                })
                self._notify(node.node_id, NodeStatus.UNAVAILABLE, reason)

            elif elapsed >= self.degraded_threshold_sec and node.status == NodeStatus.HEALTHY:
                node.status = NodeStatus.DEGRADED
                reason = f"Heartbeat delayed {round(elapsed, 1)}s (exceeded {self.degraded_threshold_sec}s threshold)"
                node.security_state = f"DEGRADED: {reason}"
                events.append({
                    "node_id": node.node_id,
                    "previous_status": NodeStatus.HEALTHY.value,
                    "new_status": NodeStatus.DEGRADED.value,
                    "reason": reason,
                    "elapsed_sec": round(elapsed, 1),
                })
                self._notify(node.node_id, NodeStatus.DEGRADED, reason)

        return events

    def get_cluster_health_summary(self) -> Dict[str, Any]:
        """Returns aggregate cluster telemetry and health status."""
        nodes = self.registry.list_nodes()
        total_vram = sum(n.vram_total_gb for n in nodes)
        used_vram = sum(n.vram_used_gb for n in nodes)
        total_ram = sum(n.ram_total_gb for n in nodes)
        used_ram = sum(n.ram_used_gb for n in nodes)
        active_jobs = sum(n.active_jobs for n in nodes)

        healthy_count = sum(1 for n in nodes if n.status == NodeStatus.HEALTHY)
        degraded_count = sum(1 for n in nodes if n.status == NodeStatus.DEGRADED)
        unavailable_count = sum(1 for n in nodes if n.status == NodeStatus.UNAVAILABLE)
        quarantined_count = sum(1 for n in nodes if n.status == NodeStatus.QUARANTINED)

        return {
            "total_nodes": len(nodes),
            "healthy_nodes": healthy_count,
            "degraded_nodes": degraded_count,
            "unavailable_nodes": unavailable_count,
            "quarantined_nodes": quarantined_count,
            "total_vram_gb": round(total_vram, 2),
            "used_vram_gb": round(used_vram, 2),
            "free_vram_gb": round(max(0.0, total_vram - used_vram), 2),
            "total_ram_gb": round(total_ram, 2),
            "used_ram_gb": round(used_ram, 2),
            "active_jobs": active_jobs,
        }
