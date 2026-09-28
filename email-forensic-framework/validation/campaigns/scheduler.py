"""
Validation Campaign Scheduler.
Supports scheduled runs, time jitter, rotation, and maintenance window constraints.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time
import random


class ScheduleFrequency(str, Enum):
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    POST_DEPLOYMENT = "POST_DEPLOYMENT"
    ON_RULE_CHANGE = "ON_RULE_CHANGE"


@dataclass
class CampaignSchedule:
    schedule_id: str
    campaign_id: str
    frequency: ScheduleFrequency
    is_active: bool = True
    maintenance_window_start: Optional[str] = "02:00"  # 02:00 AM UTC
    maintenance_window_end: Optional[str] = "04:00"    # 04:00 AM UTC
    enable_jitter: bool = True
    last_run_timestamp: Optional[float] = None
    next_run_timestamp: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "campaign_id": self.campaign_id,
            "frequency": self.frequency.value if isinstance(self.frequency, ScheduleFrequency) else self.frequency,
            "is_active": self.is_active,
            "maintenance_window_start": self.maintenance_window_start,
            "maintenance_window_end": self.maintenance_window_end,
            "enable_jitter": self.enable_jitter,
            "last_run_timestamp": self.last_run_timestamp,
            "next_run_timestamp": self.next_run_timestamp,
        }


class ValidationScheduler:
    """Manages scheduled campaign triggers and maintenance windows."""

    def __init__(self):
        self._schedules: Dict[str, CampaignSchedule] = {}
        self._load_defaults()

    def _load_defaults(self):
        s1 = CampaignSchedule(
            schedule_id="SCHED-NIGHTLY-TLS",
            campaign_id="CAMP-TLS-01",
            frequency=ScheduleFrequency.DAILY,
            is_active=True,
        )
        s2 = CampaignSchedule(
            schedule_id="SCHED-WEEKLY-CERT",
            campaign_id="CAMP-CERT-01",
            frequency=ScheduleFrequency.WEEKLY,
            is_active=True,
        )
        self._schedules[s1.schedule_id] = s1
        self._schedules[s2.schedule_id] = s2

    def register_schedule(self, schedule: CampaignSchedule) -> None:
        self._schedules[schedule.schedule_id] = schedule

    def get_schedule(self, schedule_id: str) -> Optional[CampaignSchedule]:
        return self._schedules.get(schedule_id)

    def list_schedules(self) -> List[CampaignSchedule]:
        return list(self._schedules.values())
