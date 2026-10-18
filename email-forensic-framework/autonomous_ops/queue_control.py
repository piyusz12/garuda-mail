"""Garuda Phase 35: Module F - Queue Optimization & Backpressure Controls.
Multi-tier priority scheduling, per-user fair limits, timeout enforcement,
and load shedding under resource saturation.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import time
import uuid

from fabric.models import WorkloadPriority


@dataclass
class QueuedWorkloadItem:
    item_id: str
    workload_type: str
    target_model: str
    priority: WorkloadPriority
    caller_id: str
    payload: Dict[str, Any]
    enqueued_at: float = field(default_factory=time.time)
    timeout_sec: float = 60.0
    retry_count: int = 0
    max_retries: int = 3
    is_cancelled: bool = False

    def is_expired(self) -> bool:
        return (time.time() - self.enqueued_at) > self.timeout_sec

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "workload_type": self.workload_type,
            "target_model": self.target_model,
            "priority": self.priority.value,
            "caller_id": self.caller_id,
            "enqueued_at": self.enqueued_at,
            "timeout_sec": self.timeout_sec,
            "retry_count": self.retry_count,
            "is_expired": self.is_expired(),
            "is_cancelled": self.is_cancelled,
        }


class QueueOptimizer:
    """Manages queue depth limits, backpressure shedding, and priority starvation prevention."""

    def __init__(
        self,
        max_total_queue: int = 50,
        max_per_user_concurrency: int = 4,
        max_per_model_queue: int = 20,
    ):
        self.max_total_queue = max_total_queue
        self.max_per_user_concurrency = max_per_user_concurrency
        self.max_per_model_queue = max_per_model_queue

        self._queues: Dict[WorkloadPriority, List[QueuedWorkloadItem]] = {
            WorkloadPriority.CRITICAL: [],
            WorkloadPriority.HIGH: [],
            WorkloadPriority.NORMAL: [],
            WorkloadPriority.LOW: [],
            WorkloadPriority.BACKGROUND: [],
        }
        self._user_active_count: Dict[str, int] = {}
        self._backpressure_active: bool = False

    @property
    def total_queued(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def enqueue(
        self,
        workload_type: str,
        target_model: str,
        caller_id: str,
        priority: WorkloadPriority = WorkloadPriority.NORMAL,
        payload: Optional[Dict[str, Any]] = None,
        timeout_sec: float = 60.0,
    ) -> tuple[bool, str, Optional[QueuedWorkloadItem]]:
        """Enqueues workload with backpressure and fair-use validation."""
        # 1. Check user fair concurrency limit (unless CRITICAL/incident)
        current_active = self._user_active_count.get(caller_id, 0)
        user_queued = sum(
            1 for q in self._queues.values() for it in q if it.caller_id == caller_id and not it.is_cancelled
        )
        total_user_load = current_active + user_queued
        if total_user_load >= self.max_per_user_concurrency and priority not in (
            WorkloadPriority.CRITICAL,
            WorkloadPriority.HIGH,
        ):
            return (
                False,
                f"Fair-use throttle: caller '{caller_id}' reached concurrency limit ({total_user_load}/{self.max_per_user_concurrency})",
                None,
            )

        # 2. Check total queue depth and apply backpressure
        if self.total_queued >= self.max_total_queue:
            self._backpressure_active = True
            # Shed low-priority work to reserve headroom for critical/interactive jobs
            if priority in (WorkloadPriority.LOW, WorkloadPriority.BACKGROUND):
                return (
                    False,
                    f"Backpressure applied: queue capacity exhausted ({self.total_queued}/{self.max_total_queue}). Low-priority task rejected.",
                    None,
                )

        # 3. Check per-model queue limit
        model_count = sum(
            1
            for q in self._queues.values()
            for item in q
            if item.target_model == target_model and not item.is_cancelled
        )
        if model_count >= self.max_per_model_queue and priority != WorkloadPriority.CRITICAL:
            return (
                False,
                f"Model queue limit reached for '{target_model}' ({model_count}/{self.max_per_model_queue})",
                None,
            )

        # 4. Enqueue item
        item_id = f"QUEUE-{uuid.uuid4().hex[:8].upper()}"
        item = QueuedWorkloadItem(
            item_id=item_id,
            workload_type=workload_type,
            target_model=target_model,
            priority=priority,
            caller_id=caller_id,
            payload=payload or {},
            timeout_sec=timeout_sec,
        )
        self._queues[priority].append(item)
        return True, "Enqueued successfully", item

    def dequeue_next(self) -> Optional[QueuedWorkloadItem]:
        """Dequeues the highest priority non-expired workload."""
        priority_order = [
            WorkloadPriority.CRITICAL,
            WorkloadPriority.HIGH,
            WorkloadPriority.NORMAL,
            WorkloadPriority.LOW,
            WorkloadPriority.BACKGROUND,
        ]

        for prio in priority_order:
            queue = self._queues[prio]
            while queue:
                item = queue.pop(0)
                if item.is_cancelled or item.is_expired():
                    continue
                # Update user active counter
                self._user_active_count[item.caller_id] = self._user_active_count.get(item.caller_id, 0) + 1
                return item

        self._backpressure_active = False
        return None

    def release_job(self, caller_id: str) -> None:
        """Releases slot when job completes."""
        if caller_id in self._user_active_count and self._user_active_count[caller_id] > 0:
            self._user_active_count[caller_id] -= 1

    def cancel_job(self, item_id: str) -> bool:
        """Cancels a queued job."""
        for queue in self._queues.values():
            for item in queue:
                if item.item_id == item_id:
                    item.is_cancelled = True
                    return True
        return False

    def get_queue_statistics(self) -> Dict[str, Any]:
        """Returns real-time queue health metrics."""
        return {
            "total_queued": self.total_queued,
            "max_capacity": self.max_total_queue,
            "backpressure_active": self._backpressure_active,
            "by_priority": {prio.value: len(q) for prio, q in self._queues.items()},
            "active_users_count": len(self._user_active_count),
        }

    def get_depth(self) -> int:
        """Returns current queue depth."""
        return self.total_queued

    def shed_low_priority_load(self, rejection_threshold: int = 35) -> int:
        """Sheds queued low/background priority items to alleviate queue depth."""
        shed_count = 0
        for prio in [WorkloadPriority.BACKGROUND, WorkloadPriority.LOW]:
            while self._queues[prio] and self.total_queued > rejection_threshold:
                self._queues[prio].pop()
                shed_count += 1
        return shed_count


# Aliases for unified naming
AutonomousQueueManager = QueueOptimizer
QueuedJob = QueuedWorkloadItem
PriorityLevel = WorkloadPriority
