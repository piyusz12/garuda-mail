"""Garuda Phase 35: Module N - Controlled Capacity Scaling & Resource Bounds.
Enforces explicit upper and lower operational bounds across worker pools, VRAM allocations,
and concurrent inference pipelines with cooldown enforcement.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time


@dataclass
class CapacityBounds:
    min_workers: int = 1
    max_workers: int = 4
    max_gpu_memory_budget_gb: float = 7.5  # RTX 4060 8GB safety ceiling
    max_concurrent_inference_jobs: int = 8
    max_queued_background_jobs: int = 50
    scale_up_threshold_pct: float = 85.0
    scale_down_threshold_pct: float = 25.0
    cooldown_seconds: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_workers": self.min_workers,
            "max_workers": self.max_workers,
            "max_gpu_memory_budget_gb": self.max_gpu_memory_budget_gb,
            "max_concurrent_inference_jobs": self.max_concurrent_inference_jobs,
            "max_queued_background_jobs": self.max_queued_background_jobs,
            "scale_up_threshold_pct": self.scale_up_threshold_pct,
            "scale_down_threshold_pct": self.scale_down_threshold_pct,
            "cooldown_seconds": self.cooldown_seconds,
        }


class CapacityManager:
    """Oversees bounded capacity allocations and scales within verified governance bounds."""

    def __init__(self, bounds: Optional[CapacityBounds] = None):
        self.bounds = bounds or CapacityBounds()
        self.current_worker_count: int = 2
        self.current_allocated_vram_gb: float = 4.2
        self.current_concurrent_jobs: int = 3
        self.last_scale_action_time: float = 0.0

    def evaluate_capacity_demand(
        self,
        current_queue_depth: int,
        active_jobs: int,
        total_vram_used_gb: float,
    ) -> Dict[str, Any]:
        """Evaluates current load against capacity limits and suggests bounded scale actions."""
        now = time.time()
        in_cooldown = (now - self.last_scale_action_time) < self.bounds.cooldown_seconds
        remaining_cooldown = max(0, int(self.bounds.cooldown_seconds - (now - self.last_scale_action_time)))

        load_pct = (active_jobs / max(1, self.bounds.max_concurrent_inference_jobs)) * 100.0

        decision = "STEADY"
        reason = "System load is within balanced operating envelope"

        if in_cooldown:
            decision = "COOLDOWN_ACTIVE"
            reason = f"Scale operations paused in cooldown ({remaining_cooldown}s remaining)"
        elif load_pct >= self.bounds.scale_up_threshold_pct:
            if self.current_worker_count < self.bounds.max_workers:
                decision = "SCALE_UP_RECOMMENDED"
                reason = f"Active concurrency ({active_jobs}) reached {load_pct:.1f}% of limit. Recommend activating standby worker."
            else:
                decision = "MAX_CAPACITY_REACHED"
                reason = f"At max worker ceiling ({self.bounds.max_workers}). Backpressure queue recommended."
        elif load_pct <= self.bounds.scale_down_threshold_pct and current_queue_depth == 0:
            if self.current_worker_count > self.bounds.min_workers:
                decision = "SCALE_DOWN_RECOMMENDED"
                reason = f"Low concurrency ({active_jobs}) and empty queue. Standby worker can be idled safely."

        # VRAM safety check
        vram_safe = total_vram_used_gb <= self.bounds.max_gpu_memory_budget_gb

        return {
            "decision": decision,
            "reason": reason,
            "load_pct": round(load_pct, 1),
            "current_workers": self.current_worker_count,
            "vram_used_gb": round(total_vram_used_gb, 2),
            "vram_safe": vram_safe,
            "in_cooldown": in_cooldown,
            "bounds": self.bounds.to_dict(),
        }

    def execute_bounded_scale(self, action: str) -> Dict[str, Any]:
        """Performs scale-up or scale-down within strict bounds."""
        now = time.time()
        if (now - self.last_scale_action_time) < self.bounds.cooldown_seconds:
            raise PermissionError("Capacity scaling action rejected: Cooldown period is active")

        if action == "SCALE_UP":
            if self.current_worker_count >= self.bounds.max_workers:
                raise ValueError(f"Cannot scale up: Already at maximum allowed workers ({self.bounds.max_workers})")
            self.current_worker_count += 1
            self.last_scale_action_time = now
            return {"action": "SCALE_UP", "workers": self.current_worker_count, "status": "SUCCESS"}

        elif action == "SCALE_DOWN":
            if self.current_worker_count <= self.bounds.min_workers:
                raise ValueError(f"Cannot scale down: Already at minimum allowed workers ({self.bounds.min_workers})")
            self.current_worker_count -= 1
            self.last_scale_action_time = now
            return {"action": "SCALE_DOWN", "workers": self.current_worker_count, "status": "SUCCESS"}

        else:
            raise ValueError(f"Unknown capacity scale action '{action}'")
