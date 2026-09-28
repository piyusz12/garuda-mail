"""
Phase 23 - Threat Hunt Scheduler.
Schedules and orchestrates periodic, cron, on-demand, and incident-triggered hunts.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import uuid

@dataclass
class HuntScheduleEntry:
    schedule_id: str
    hunt_id: str
    query_str: str
    schedule_type: str  # real-time, hourly, daily, weekly, on-demand, incident-triggered, cron
    cron_expression: Optional[str] = None
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    is_active: bool = True

@dataclass
class HuntRunRecord:
    hunt_run_id: str
    hunt_id: str
    start_time: datetime
    end_time: datetime
    query: str
    data_range: str
    results_count: int
    runtime_ms: float
    cost_units: int
    status: str = "COMPLETED"  # RUNNING, COMPLETED, FAILED


class HuntScheduler:
    """Manages scheduled jobs and execution records for threat hunting."""

    def __init__(self):
        self.schedules: Dict[str, HuntScheduleEntry] = {}
        self.run_history: List[HuntRunRecord] = []

    def schedule_hunt(
        self,
        hunt_id: str,
        query_str: str,
        schedule_type: str = "daily",
        cron_expression: Optional[str] = None
    ) -> HuntScheduleEntry:
        sched_id = f"SCHED-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc)
        
        # Calculate next run
        delta = timedelta(days=1)
        if schedule_type == "hourly":
            delta = timedelta(hours=1)
        elif schedule_type == "weekly":
            delta = timedelta(weeks=1)
        elif schedule_type == "real-time":
            delta = timedelta(seconds=60)

        entry = HuntScheduleEntry(
            schedule_id=sched_id,
            hunt_id=hunt_id,
            query_str=query_str,
            schedule_type=schedule_type,
            cron_expression=cron_expression,
            last_run=None,
            next_run=now + delta,
            is_active=True
        )
        self.schedules[sched_id] = entry
        return entry

    def record_run(
        self,
        hunt_id: str,
        query: str,
        data_range: str,
        results_count: int,
        runtime_ms: float,
        cost_units: int,
        start_time: datetime
    ) -> HuntRunRecord:
        record = HuntRunRecord(
            hunt_run_id=f"HUNT-RUN-{uuid.uuid4().hex[:8].upper()}",
            hunt_id=hunt_id,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            query=query,
            data_range=data_range,
            results_count=results_count,
            runtime_ms=runtime_ms,
            cost_units=cost_units,
            status="COMPLETED"
        )
        self.run_history.append(record)
        return record

    def list_due_schedules(self, current_time: Optional[datetime] = None) -> List[HuntScheduleEntry]:
        now = current_time or datetime.now(timezone.utc)
        due = []
        for s in self.schedules.values():
            if s.is_active and s.next_run and s.next_run <= now:
                due.append(s)
        return due
